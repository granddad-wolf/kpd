//! Runtime application state and key handling: the terminal-aware glue that
//! connects the pure [`state::State`] machine to crossterm key events, the
//! clipboard, and the unlock flow (local file or cloud storage). Secrets are
//! held only where the `State` machine or [`ClipboardGuard`] already owns them.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use kpd_clipboard::{copy_autoclear, ClipboardGuard};
use kpd_crypto::CompositeKey;
use kpd_kdbx::{DbHandle, EntryField, SaveOptions};
use kpd_plugin_runtime::{Permission, PluginManifest};
use kpd_storage::{from_spec, Storage, StorageError};

use crate::state::{AddEntryOutcome, Move, Prompt, Screen, State};
use crate::{AppConfig, DbLocation};

/// What the event loop should do after a key is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Continue,
    Quit,
}

/// A transient status-bar message.
#[derive(Debug, Clone)]
pub enum Status {
    Idle,
    Info(String),
    /// A secret was just copied; the renderer derives the remaining auto-clear
    /// time from `copied_at` and `timeout`.
    Copy {
        copied_at: Instant,
        timeout: Duration,
    },
}

/// The master password being typed on the unlock screen.
///
/// Held as a plain `String` only while being typed. On submit it is moved into
/// [`CompositeKey`] (which zeroizes it on drop), so no plaintext copy survives.
/// Intentionally does not implement `Debug` and is never printed.
#[derive(Default)]
struct UnlockInput {
    password: String,
}

impl UnlockInput {
    fn push(&mut self, c: char) {
        self.password.push(c);
    }

    fn pop(&mut self) {
        self.password.pop();
    }

    fn len(&self) -> usize {
        self.password.len()
    }

    fn take(&mut self) -> String {
        std::mem::take(&mut self.password)
    }
}

/// The cloud backend and the remote revision the session was opened at.
struct CloudSession {
    storage: Box<dyn Storage>,
    /// Passed as `expected_revision` on save so a concurrent remote change
    /// surfaces as a conflict instead of being overwritten.
    revision: Option<String>,
}

/// Work deferred out of the key handler because it does network I/O.
///
/// The event loop redraws the "busy" message first, then calls
/// [`App::run_pending`] so the blocking fetch/upload does not hide its own
/// progress.
enum Pending {
    /// Fetch and decrypt the remote database for this key.
    Unlock {
        key: CompositeKey,
        storage: Box<dyn Storage>,
    },
    /// Upload the serialized in-memory database. `upgraded` carries whether
    /// the save is the one that promoted the database to KDBX 4.1; `force`
    /// uploads without the revision check (overwrite after a conflict).
    Save { upgraded: bool, force: bool },
    /// Re-fetch the remote database after a save conflict, discarding local
    /// edits.
    Reload,
}

/// A plugin awaiting the user's consent to its declared capabilities.
#[derive(Debug, Clone)]
pub struct PluginConsent {
    /// The component that would run.
    pub wasm: std::path::PathBuf,
    /// Manifest display name.
    pub name: String,
    /// Optional manifest description.
    pub description: Option<String>,
    /// Capabilities the manifest declares.
    pub capabilities: Vec<Permission>,
}

/// The full runtime application state.
pub struct App {
    pub config: AppConfig,
    pub state: State,
    /// The write-path handle owning the decrypted `keepass::Database`; `None`
    /// while locked.
    handle: Option<DbHandle>,
    /// The session composite key for save; zeroized on lock/quit.
    key: Option<CompositeKey>,
    unlock: UnlockInput,
    unlock_error: Option<String>,
    status: Status,
    clipboard_guard: Option<ClipboardGuard>,
    /// The cloud backend for a remote database; `None` for local files and
    /// while locked.
    cloud: Option<CloudSession>,
    /// Network work to run right after the next redraw.
    pending: Option<Pending>,
    /// Message shown while `pending` work runs (e.g. `fetching <url>`).
    busy: Option<String>,
    /// Save conflict awaiting a choice: the short location label.
    conflict: Option<String>,
    /// A plugin manifest awaiting consent, if any.
    consent: Option<PluginConsent>,
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            state: State::default(),
            handle: None,
            key: None,
            unlock: UnlockInput::default(),
            unlock_error: None,
            status: Status::Idle,
            clipboard_guard: None,
            cloud: None,
            pending: None,
            busy: None,
            conflict: None,
            consent: None,
        }
    }

    /// The location label of an unresolved save conflict, if any.
    pub fn conflict_label(&self) -> Option<&str> {
        self.conflict.as_deref()
    }

    /// The plugin manifest awaiting consent, if any.
    pub fn consent(&self) -> Option<&PluginConsent> {
        self.consent.as_ref()
    }

    /// Key hints for the bottom bar, contextual to the active screen or modal.
    pub fn key_tips(&self) -> Vec<(&'static str, &'static str)> {
        if self.busy.is_some() {
            return vec![("…", "working")];
        }
        if self.conflict.is_some() {
            return vec![
                ("R", "Reload remote"),
                ("O", "Overwrite remote"),
                ("Esc", "Dismiss"),
            ];
        }
        if self.state.plugin_result.is_some() {
            return vec![("Any", "Close")];
        }
        if self.consent.is_some() {
            return vec![("Y", "Allow"), ("N", "Cancel")];
        }
        if self.state.plugin_menu.is_some() {
            return vec![("↑↓", "Move"), ("Enter", "Review"), ("Esc", "Close")];
        }
        if self.state.prompt != Prompt::None {
            let confirm = matches!(
                self.state.prompt,
                Prompt::ConfirmDeleteEntry { .. }
                    | Prompt::ConfirmDeleteGroup { .. }
                    | Prompt::ConfirmSave
            );
            return if confirm {
                vec![("Y", "Confirm"), ("N", "Cancel")]
            } else {
                vec![("Enter", "Submit"), ("Esc", "Cancel"), ("⌫", "Delete")]
            };
        }
        match self.state.screen {
            Screen::Unlock => vec![("Enter", "Unlock"), ("Esc", "Quit")],
            Screen::Browse => vec![
                ("Q", "Quit"),
                ("L", "Lock"),
                ("^S", "Save"),
                ("P", "Plugins"),
                ("^F", "Find"),
                ("^C", "Copy"),
                ("Tab", "Pane"),
                ("Enter", "Open"),
                ("A", "Add"),
                ("E", "Edit"),
                ("D", "Delete"),
            ],
            Screen::Detail => vec![
                ("Q", "Quit"),
                ("L", "Lock"),
                ("Esc", "Back"),
                ("^C", "Copy"),
                ("R", "Reveal"),
                ("E", "Edit"),
                ("D", "Delete"),
                ("^S", "Save"),
            ],
        }
    }

    /// Whether deferred network work is waiting to run (the event loop must
    /// redraw and then call [`App::run_pending`]).
    pub const fn is_busy(&self) -> bool {
        self.pending.is_some()
    }

    /// The in-flight message to show while busy, if any.
    pub fn busy_label(&self) -> Option<&str> {
        self.busy.as_deref()
    }

    /// Run the deferred work queued by the last key press. Blocking: callers
    /// redraw first so the busy message is visible during the network I/O.
    pub fn run_pending(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        self.busy = None;
        match pending {
            Pending::Unlock { key, storage } => self.finish_cloud_unlock(key, storage),
            Pending::Save { upgraded, force } => self.save_cloud(upgraded, force),
            Pending::Reload => self.reload_remote(),
        }
    }

    /// Length of the masked master password (for rendering `*` placeholders).
    pub fn unlock_password_len(&self) -> usize {
        self.unlock.len()
    }

    /// The inline unlock error, if the last attempt failed.
    pub fn unlock_error(&self) -> Option<&str> {
        self.unlock_error.as_deref()
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    /// Handle one key press, returning whether the app should quit.
    pub fn handle_key(&mut self, key: &KeyEvent) -> Control {
        // Deferred network work owns the session until it finishes.
        if self.pending.is_some() {
            return Control::Continue;
        }
        // A save conflict captures the keyboard until resolved or dismissed.
        if self.conflict.is_some() {
            return self.handle_conflict_key(key);
        }
        // A plugin consent prompt captures the keyboard until answered.
        if self.consent.is_some() {
            return self.handle_consent_key(key);
        }
        // A plugin-output modal captures the keyboard until dismissed.
        if self.state.plugin_result.is_some() {
            self.state.dismiss_plugin_result();
            return Control::Continue;
        }
        // A plugin picker captures the keyboard until it closes.
        if self.state.plugin_menu.is_some() {
            return self.handle_plugin_menu_key(key);
        }
        // A prompt captures the keyboard until committed or cancelled.
        if self.state.prompt != Prompt::None {
            return self.handle_prompt_key(key);
        }

        match self.state.screen {
            Screen::Unlock => self.handle_unlock_key(key),
            Screen::Browse => self.handle_browse_key(key),
            Screen::Detail => self.handle_detail_key(key),
        }
    }

    /// Handle a key while the plugin consent prompt is open: `Y`/`Enter`
    /// grants the manifest's capabilities and proceeds, `N`/`Esc` cancels.
    fn handle_consent_key(&mut self, key: &KeyEvent) -> Control {
        match key.code {
            KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                if let Some(consent) = self.consent.take() {
                    self.status = Status::Info(format!(
                        "{}: granted {}",
                        consent.name,
                        consent
                            .capabilities
                            .iter()
                            .map(|permission| permission.label())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    self.state
                        .begin_plugin_command(consent.wasm, consent.capabilities);
                }
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                if let Some(consent) = self.consent.take() {
                    self.status = Status::Info(format!("cancelled {}", consent.name));
                }
            }
            _ => {}
        }
        Control::Continue
    }

    /// Handle a key while the save-conflict modal is open: `R` reloads the
    /// remote (discarding local edits), `O` overwrites it, `Esc` dismisses.
    fn handle_conflict_key(&mut self, key: &KeyEvent) -> Control {
        let label = self.conflict.clone().unwrap_or_default();
        match key.code {
            KeyCode::Esc => {
                self.conflict = None;
                self.status = Status::Info(
                    "conflict dismissed — local edits kept; save again to retry".to_string(),
                );
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.conflict = None;
                self.busy = Some(format!("reloading {label}"));
                self.pending = Some(Pending::Reload);
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                self.conflict = None;
                let upgraded = match self.handle.as_mut() {
                    Some(handle) => {
                        let upgraded = !handle.is_kdbx41();
                        if upgraded {
                            handle.upgrade_to_kdbx41();
                        }
                        upgraded
                    }
                    None => {
                        self.status = Status::Info("not unlocked".to_string());
                        return Control::Continue;
                    }
                };
                self.begin_cloud_save(upgraded, true);
            }
            _ => {}
        }
        Control::Continue
    }

    /// Handle a key while the plugin picker is open.
    fn handle_plugin_menu_key(&mut self, key: &KeyEvent) -> Control {
        match key.code {
            KeyCode::Esc => {
                self.state.close_plugin_menu();
                Control::Continue
            }
            KeyCode::Up => {
                self.state.plugin_menu_navigate(Move::Up);
                Control::Continue
            }
            KeyCode::Down => {
                self.state.plugin_menu_navigate(Move::Down);
                Control::Continue
            }
            KeyCode::Enter => {
                if let Some(wasm) = self.state.plugin_menu_selected().cloned() {
                    match PluginManifest::load(&wasm) {
                        Ok(manifest) => {
                            self.state.close_plugin_menu();
                            self.consent = Some(PluginConsent {
                                wasm,
                                name: manifest.name,
                                description: manifest.description,
                                capabilities: manifest.capabilities,
                            });
                        }
                        Err(err) => {
                            self.status = Status::Info(format!("plugin manifest: {err}"));
                        }
                    }
                }
                Control::Continue
            }
            _ => Control::Continue,
        }
    }

    fn handle_unlock_key(&mut self, key: &KeyEvent) -> Control {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => Control::Quit,
            // Ctrl+C on the unlock screen also quits: nothing is decrypted yet.
            KeyCode::Char('c') if ctrl => Control::Quit,
            KeyCode::Enter => {
                self.try_unlock();
                Control::Continue
            }
            KeyCode::Backspace => {
                self.unlock.pop();
                self.unlock_error = None;
                Control::Continue
            }
            KeyCode::Char(c) if !ctrl && !key.modifiers.contains(KeyModifiers::ALT) => {
                self.unlock.push(c);
                self.unlock_error = None;
                Control::Continue
            }
            _ => Control::Continue,
        }
    }

    fn try_unlock(&mut self) {
        // The password is moved into `CompositeKey`, which zeroizes it on drop.
        let password = self.unlock.take();

        let mut key = CompositeKey::new();
        if let Some(key_file) = &self.config.key_file {
            key = key.with_key_file_path(key_file.clone());
        }
        key = key.with_password(password);

        match &self.config.location {
            DbLocation::Local(path) => match DbHandle::open(path, &key) {
                Ok(handle) => {
                    let view = handle.view();
                    self.unlock_error = None;
                    self.handle = Some(handle);
                    self.key = Some(key);
                    self.cloud = None;
                    self.state.unlock(view);
                    self.status = Status::Idle;
                }
                Err(err) => self.fail_unlock(err.to_string()),
            },
            DbLocation::Cloud(spec) => {
                // Validate the backend config now (bad URLs fail before the key
                // is parked); the network fetch is deferred to `run_pending`.
                match from_spec(spec.clone()) {
                    Ok(storage) => {
                        self.unlock_error = None;
                        self.busy =
                            Some(format!("fetching {}", self.config.location.short_label()));
                        self.pending = Some(Pending::Unlock { key, storage });
                    }
                    Err(err) => self.fail_unlock(err.to_string()),
                }
            }
        }
    }

    /// Surface an unlock failure and force the password to be re-entered.
    fn fail_unlock(&mut self, message: String) {
        // Any parked key is dropped here and zeroizes itself.
        self.unlock_error = Some(message);
        self.unlock = UnlockInput::default();
        self.busy = None;
    }

    /// Fetch the cloud database, decrypt it with the session key, and enter the
    /// browse screen. Called from [`App::run_pending`] after the busy message has
    /// been drawn.
    fn finish_cloud_unlock(&mut self, key: CompositeKey, storage: Box<dyn Storage>) {
        let Ok(runtime) = tokio::runtime::Runtime::new() else {
            self.fail_unlock("could not start the cloud runtime".to_string());
            return;
        };
        let fetched = runtime.block_on(async {
            let meta = storage.meta().await?;
            let bytes = storage.read().await?;
            Ok::<_, StorageError>((bytes, meta.revision))
        });

        let (bytes, revision) = match fetched {
            Ok(fetched) => fetched,
            Err(err) => {
                self.fail_unlock(format!("cloud fetch failed: {err}"));
                return;
            }
        };

        match DbHandle::open_bytes(&bytes, &key) {
            Ok(handle) => {
                let view = handle.view();
                self.unlock_error = None;
                self.handle = Some(handle);
                self.key = Some(key);
                self.cloud = Some(CloudSession { storage, revision });
                self.state.unlock(view);
                self.status = Status::Info(format!(
                    "loaded {} bytes from {}",
                    bytes.len(),
                    self.config.location.short_label()
                ));
            }
            Err(err) => self.fail_unlock(err.to_string()),
        }
    }

    fn handle_browse_key(&mut self, key: &KeyEvent) -> Control {
        // While typing a search query, printable characters go to the query.
        if self.state.searching {
            return self.handle_search_key(key);
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => Control::Quit,
            KeyCode::Char('l') | KeyCode::Char('L') => {
                self.lock();
                Control::Continue
            }
            KeyCode::Char('f') if ctrl => {
                self.state.begin_search();
                Control::Continue
            }
            KeyCode::Char('c') if ctrl => {
                self.copy_selected();
                Control::Continue
            }
            KeyCode::Char('s') if ctrl => {
                self.state.begin_confirm_save();
                Control::Continue
            }
            KeyCode::Char('a') | KeyCode::Char('A') if !ctrl => {
                self.state.begin_add_entry();
                Control::Continue
            }
            KeyCode::Char('g') | KeyCode::Char('G') if !ctrl => {
                self.state.begin_add_group();
                Control::Continue
            }
            KeyCode::Char('e') | KeyCode::Char('E') if !ctrl => {
                self.begin_edit_selected_password();
                Control::Continue
            }
            KeyCode::Char('d') | KeyCode::Char('D') if !ctrl => {
                self.begin_delete_selected_entry();
                Control::Continue
            }
            KeyCode::Char('x') | KeyCode::Char('X') if !ctrl => {
                self.begin_delete_current_group();
                Control::Continue
            }
            KeyCode::Char('p') | KeyCode::Char('P') if !ctrl => {
                self.open_plugin_menu();
                Control::Continue
            }
            KeyCode::Up => {
                self.state.navigate(Move::Up);
                Control::Continue
            }
            KeyCode::Down => {
                self.state.navigate(Move::Down);
                Control::Continue
            }
            KeyCode::Tab => {
                self.state.toggle_focus();
                Control::Continue
            }
            KeyCode::Enter => {
                self.state.open_selected();
                Control::Continue
            }
            _ => Control::Continue,
        }
    }

    fn handle_search_key(&mut self, key: &KeyEvent) -> Control {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => {
                self.state.cancel_search();
                Control::Continue
            }
            KeyCode::Enter => {
                self.state.commit_search();
                Control::Continue
            }
            KeyCode::Backspace => {
                self.state.backspace_search();
                Control::Continue
            }
            KeyCode::Char('c') if ctrl => {
                self.copy_selected();
                Control::Continue
            }
            KeyCode::Up => {
                self.state.navigate(Move::Up);
                Control::Continue
            }
            KeyCode::Down => {
                self.state.navigate(Move::Down);
                Control::Continue
            }
            KeyCode::Char(c) if !ctrl && !key.modifiers.contains(KeyModifiers::ALT) => {
                self.state.type_search(c);
                Control::Continue
            }
            _ => Control::Continue,
        }
    }

    fn handle_detail_key(&mut self, key: &KeyEvent) -> Control {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc | KeyCode::Left => {
                self.state.close_detail();
                Control::Continue
            }
            KeyCode::Char('q') | KeyCode::Char('Q') => Control::Quit,
            KeyCode::Char('l') | KeyCode::Char('L') => {
                self.lock();
                Control::Continue
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.state.toggle_reveal();
                Control::Continue
            }
            KeyCode::Char('c') if ctrl => {
                self.copy_selected();
                Control::Continue
            }
            KeyCode::Char('s') if ctrl => {
                self.state.begin_confirm_save();
                Control::Continue
            }
            KeyCode::Char('e') | KeyCode::Char('E') if !ctrl => {
                self.begin_edit_detail_field();
                Control::Continue
            }
            KeyCode::Char('d') | KeyCode::Char('D') if !ctrl => {
                self.begin_delete_detail_entry();
                Control::Continue
            }
            KeyCode::Up => {
                self.state.detail_navigate(Move::Up);
                Control::Continue
            }
            KeyCode::Down => {
                self.state.detail_navigate(Move::Down);
                Control::Continue
            }
            _ => Control::Continue,
        }
    }

    /// Begin editing the selected entry's password (the `e` key while browsing).
    fn begin_edit_selected_password(&mut self) {
        let Some(uuid) = self.state.selected_entry().map(|entry| entry.uuid) else {
            self.status = Status::Info("nothing to edit".to_string());
            return;
        };
        self.state.begin_edit_field(uuid, EntryField::Password);
    }

    /// Begin confirming deletion of the selected entry (`d` while browsing).
    fn begin_delete_selected_entry(&mut self) {
        let Some(uuid) = self.state.selected_entry().map(|entry| entry.uuid) else {
            self.status = Status::Info("nothing to delete".to_string());
            return;
        };
        self.state.begin_confirm_delete_entry(uuid);
    }

    /// Begin confirming deletion of the current group (`x` while browsing).
    fn begin_delete_current_group(&mut self) {
        let Some(uuid) = self.state.selected_group_uuid() else {
            self.status = Status::Info("no group selected".to_string());
            return;
        };
        self.state.begin_confirm_delete_group(uuid);
    }

    /// Begin editing the focused detail row (`e` while viewing an entry).
    fn begin_edit_detail_field(&mut self) {
        let Some(field) = self.state.detail_edit_field() else {
            self.status = Status::Info("this field cannot be edited".to_string());
            return;
        };
        let Some(uuid) = self.state.detail_entry().map(|entry| entry.uuid) else {
            self.status = Status::Info("nothing to edit".to_string());
            return;
        };
        self.state.begin_edit_field(uuid, field);
    }

    /// Begin confirming deletion of the entry being viewed (`d` in detail).
    fn begin_delete_detail_entry(&mut self) {
        let Some(uuid) = self.state.detail_entry().map(|entry| entry.uuid) else {
            self.status = Status::Info("nothing to delete".to_string());
            return;
        };
        self.state.begin_confirm_delete_entry(uuid);
    }

    /// Handle a key while a prompt is active: text prompts capture printable
    /// input, `Backspace` deletes, `Enter` commits, and `Esc` cancels. The
    /// `Confirm*` prompts accept `y`/`Y` (or `Enter`) as "yes" and anything
    /// else as "cancel".
    fn handle_prompt_key(&mut self, key: &KeyEvent) -> Control {
        let is_confirm = matches!(
            self.state.prompt,
            Prompt::ConfirmDeleteEntry { .. }
                | Prompt::ConfirmDeleteGroup { .. }
                | Prompt::ConfirmSave
        );

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);

        match key.code {
            KeyCode::Esc => {
                self.state.cancel_prompt();
                Control::Continue
            }
            KeyCode::Enter => {
                self.commit_prompt();
                Control::Continue
            }
            KeyCode::Char('y') | KeyCode::Char('Y') if is_confirm => {
                self.commit_prompt();
                Control::Continue
            }
            KeyCode::Backspace if !is_confirm => {
                self.state.backspace_input();
                Control::Continue
            }
            KeyCode::Char(c) if !is_confirm && !ctrl && !alt => {
                self.state.type_input(c);
                Control::Continue
            }
            _ if is_confirm => {
                // Any other key cancels a confirmation.
                self.state.cancel_prompt();
                Control::Continue
            }
            _ => Control::Continue,
        }
    }

    /// Execute the mutation or transition behind the active prompt on `Enter`.
    fn commit_prompt(&mut self) {
        // The add-entry flow is multi-step; advance it, and run the mutation
        // once the final (password) step completes.
        if matches!(
            self.state.prompt,
            Prompt::AddEntryTitle
                | Prompt::AddEntryUsername { .. }
                | Prompt::AddEntryPassword { .. }
        ) {
            match self.state.commit_add_entry() {
                AddEntryOutcome::Continue => {}
                AddEntryOutcome::Complete {
                    title,
                    username,
                    password,
                } => {
                    let Some(group_uuid) = self.state.selected_group_uuid() else {
                        self.status = Status::Info("no group selected".to_string());
                        return;
                    };
                    self.mutate(
                        false,
                        |handle| handle.add_entry(group_uuid, &title, &username, &password),
                        "entry added",
                    );
                }
            }
            return;
        }

        match std::mem::take(&mut self.state.prompt) {
            Prompt::None => {}
            Prompt::AddGroupName => {
                let name = std::mem::take(&mut self.state.input);
                let Some(group_uuid) = self.state.selected_group_uuid() else {
                    self.status = Status::Info("no group selected".to_string());
                    return;
                };
                self.mutate(
                    false,
                    |handle| handle.add_group(group_uuid, &name),
                    "group added",
                );
            }
            Prompt::EditField { entry_uuid, field } => {
                let value = std::mem::take(&mut self.state.input);
                self.mutate(
                    true,
                    move |handle| handle.set_entry_field(entry_uuid, field, &value),
                    "entry updated",
                );
            }
            Prompt::ConfirmDeleteEntry { entry_uuid } => {
                self.mutate(
                    true,
                    move |handle| handle.delete_entry(entry_uuid),
                    "entry deleted",
                );
            }
            Prompt::ConfirmDeleteGroup { group_uuid } => {
                self.mutate(
                    true,
                    move |handle| handle.delete_group(group_uuid),
                    "group deleted",
                );
            }
            Prompt::ConfirmSave => self.save(),
            Prompt::PluginCommand { wasm, permissions } => {
                let command_line = std::mem::take(&mut self.state.input);
                self.run_plugin(&wasm, &permissions, &command_line);
            }
            Prompt::AddEntryTitle
            | Prompt::AddEntryUsername { .. }
            | Prompt::AddEntryPassword { .. } => {
                unreachable!("add-entry prompts are handled above");
            }
        }
    }

    /// Run a mutation against the write handle, refresh the view from it, clear
    /// the prompt, and surface the outcome in the status bar. `clear_clipboard`
    /// drops the clipboard guard for mutations that may change a copied secret.
    fn mutate<T>(
        &mut self,
        clear_clipboard: bool,
        f: impl FnOnce(&mut DbHandle) -> Result<T, kpd_kdbx::KdbxError>,
        success: &str,
    ) {
        match self.handle.as_mut().map(f) {
            Some(Ok(_)) => {
                if let Some(handle) = &self.handle {
                    let view = handle.view();
                    self.state.replace_db(view);
                }
                // If the entry being viewed was just removed, leave the now-empty
                // detail view and return to browsing.
                if self.state.screen == Screen::Detail && self.state.detail_entry().is_none() {
                    self.state.close_detail();
                }
                if clear_clipboard {
                    self.clear_clipboard_guard();
                }
                self.state.cancel_prompt();
                self.status = Status::Info(success.to_string());
            }
            Some(Err(err)) => {
                self.status = Status::Info(format!("{err}"));
            }
            None => {
                self.status = Status::Info("not unlocked".to_string());
            }
        }
    }

    /// Open the plugin picker with every `.wasm` discovered in the plugin dirs.
    fn open_plugin_menu(&mut self) {
        let paths = discover_plugins();
        if paths.is_empty() {
            self.status = Status::Info(format!("no plugins found in {}", plugins_dir_hint()));
            return;
        }
        self.state.open_plugin_menu(paths);
    }

    /// Run the selected plugin against the open database's entries and show its
    /// output in a modal.
    fn run_plugin(
        &mut self,
        wasm: &std::path::Path,
        permissions: &[Permission],
        command_line: &str,
    ) {
        use kpd_plugin_runtime::{EntrySummary, Limits, PluginRuntime, RunContext};

        let mut parts = command_line.split_whitespace();
        let Some(command) = parts.next() else {
            self.state.cancel_prompt();
            self.status = Status::Info("type a plugin command (e.g. count)".to_string());
            return;
        };
        let args: Vec<String> = parts.map(str::to_string).collect();

        let entries = match &self.state.db {
            Some(db) => db
                .all_entries()
                .into_iter()
                .filter_map(|entry_ref| {
                    db.entry(entry_ref.entry_uuid).map(|entry| EntrySummary {
                        uuid: entry.uuid.to_string(),
                        title: entry.title.clone(),
                        username: entry.username.clone(),
                    })
                })
                .collect(),
            None => Vec::new(),
        };

        let runtime = PluginRuntime::new();
        let mut plugin = match runtime.load(wasm, permissions, Limits::default()) {
            Ok(plugin) => plugin,
            Err(err) => {
                self.state.cancel_prompt();
                self.status = Status::Info(format!("load plugin failed: {err}"));
                return;
            }
        };

        let mut ctx = RunContext {
            entries,
            ..Default::default()
        };
        match plugin.run(command, &args, &mut ctx) {
            Ok(output) => {
                let mut text = output;
                for line in &ctx.logs {
                    text.push_str("\nlog: ");
                    text.push_str(line);
                }
                for copied in &ctx.copied {
                    text.push_str("\ncopied: ");
                    text.push_str(copied);
                }
                self.state.set_plugin_result(text);
            }
            Err(err) => {
                self.state.cancel_prompt();
                self.status = Status::Info(format!("plugin failed: {err}"));
            }
        }
    }

    /// Guarded save of the database to its original path.
    fn save(&mut self) {
        let Some(handle) = self.handle.as_mut() else {
            self.status = Status::Info("not unlocked".to_string());
            return;
        };
        // The writer only produces KDBX 4.1; upgrade KDBX 4.0 (and older) on
        // save. The original file is preserved by the `.bak` backup.
        let upgraded = !handle.is_kdbx41();
        if upgraded {
            handle.upgrade_to_kdbx41();
        }
        let Some(key) = self.key.as_ref() else {
            self.status = Status::Info("no session key".to_string());
            return;
        };

        if self.config.location.is_cloud() {
            // Defer the upload so the event loop can draw the busy message; the
            // upgrade above is already in memory, so `save_cloud` only needs to
            // serialize and push.
            self.begin_cloud_save(upgraded, false);
            return;
        }

        match handle.save(key, &SaveOptions::default()) {
            Ok(report) => {
                let mut msg = format!("saved {} bytes", report.bytes_written);
                if report.backup_path.is_some() {
                    msg.push_str(" (backup written)");
                }
                if upgraded {
                    msg.push_str(" — upgraded to KDBX 4.1");
                }
                if !report.warnings.is_empty() {
                    msg.push_str(" — warnings present");
                }
                self.status = Status::Info(msg);
            }
            Err(err) => self.status = Status::Info(format!("save failed: {err}")),
        }
    }

    /// Queue a cloud upload. `force` skips the revision check (overwrite after
    /// a conflict); otherwise the session revision is the precondition.
    fn begin_cloud_save(&mut self, upgraded: bool, force: bool) {
        self.busy = Some(format!("saving to {}", self.config.location.short_label()));
        self.pending = Some(Pending::Save { upgraded, force });
    }

    /// Serialize the in-memory database and upload it with the revision the
    /// session was opened at. A revision mismatch opens the conflict modal and
    /// leaves the remote untouched.
    fn save_cloud(&mut self, upgraded: bool, force: bool) {
        let Some(handle) = self.handle.as_ref() else {
            self.status = Status::Info("not unlocked".to_string());
            return;
        };
        let Some(key) = self.key.as_ref() else {
            self.status = Status::Info("no session key".to_string());
            return;
        };
        let serialized = handle.serialize(key);
        let bytes = match serialized {
            Ok(bytes) => bytes,
            Err(err) => {
                self.status = Status::Info(format!("save failed: {err}"));
                return;
            }
        };

        let Some(cloud) = self.cloud.as_mut() else {
            self.status = Status::Info("no cloud session — unlock again".to_string());
            return;
        };
        let Ok(runtime) = tokio::runtime::Runtime::new() else {
            self.status = Status::Info("could not start the cloud runtime".to_string());
            return;
        };
        let label = self.config.location.short_label();
        let expected = if force {
            None
        } else {
            cloud.revision.as_deref()
        };
        match runtime.block_on(cloud.storage.write(&bytes, expected)) {
            Ok(meta) => {
                cloud.revision = meta.revision;
                let mut msg = format!("saved {} bytes to {}", bytes.len(), label);
                if force {
                    msg.push_str(" (overwrote remote)");
                }
                if upgraded {
                    msg.push_str(" — upgraded to KDBX 4.1");
                }
                self.status = Status::Info(msg);
            }
            Err(StorageError::Conflict(detail)) if detail.contains("locked") => {
                self.status = Status::Info(format!(
                    "conflict: {label} is locked by another client — try again shortly"
                ));
            }
            Err(StorageError::Conflict(_)) => {
                self.conflict = Some(label);
                self.status = Status::Info(
                    "save conflict — R reload remote · O overwrite remote".to_string(),
                );
            }
            Err(err) => self.status = Status::Info(format!("save failed: {err}")),
        }
    }

    /// Re-fetch the remote database after a conflict and replace the in-memory
    /// copy, discarding local edits.
    fn reload_remote(&mut self) {
        let Some(key) = self.key.as_ref() else {
            self.status = Status::Info("no session key".to_string());
            return;
        };
        let Some(cloud) = self.cloud.as_ref() else {
            self.status = Status::Info("no cloud session — unlock again".to_string());
            return;
        };
        let Ok(runtime) = tokio::runtime::Runtime::new() else {
            self.status = Status::Info("could not start the cloud runtime".to_string());
            return;
        };
        let fetched = runtime.block_on(async {
            let meta = cloud.storage.meta().await?;
            let bytes = cloud.storage.read().await?;
            Ok::<_, StorageError>((bytes, meta.revision))
        });

        let (bytes, revision) = match fetched {
            Ok(fetched) => fetched,
            Err(err) => {
                self.status = Status::Info(format!("reload failed: {err}"));
                return;
            }
        };

        match DbHandle::open_bytes(&bytes, key) {
            Ok(handle) => {
                let view = handle.view();
                self.handle = Some(handle);
                if let Some(cloud) = self.cloud.as_mut() {
                    cloud.revision = revision;
                }
                self.state.replace_db(view);
                if self.state.screen == Screen::Detail && self.state.detail_entry().is_none() {
                    self.state.close_detail();
                }
                self.clear_clipboard_guard();
                self.status = Status::Info(format!(
                    "reloaded {} bytes from {} — local edits discarded",
                    bytes.len(),
                    self.config.location.short_label()
                ));
            }
            Err(err) => self.status = Status::Info(format!("reload failed: {err}")),
        }
    }

    /// Clear any copied secret immediately.
    fn clear_clipboard_guard(&mut self) {
        if let Some(mut guard) = self.clipboard_guard.take() {
            guard.clear_now();
        }
    }

    fn copy_selected(&mut self) {
        let Some(secret) = self.state.secret_to_copy() else {
            self.status = Status::Info("nothing to copy".to_string());
            return;
        };
        match copy_autoclear(secret, self.config.clipboard_timeout) {
            Ok(guard) => {
                // Replacing the guard drops the previous one, which zeroizes its
                // secret. The old auto-clear timer is harmless: it only clears
                // the clipboard if it still holds the exact old text, so it will
                // not clobber this new copy.
                self.clipboard_guard = Some(guard);
                self.status = Status::Copy {
                    copied_at: Instant::now(),
                    timeout: self.config.clipboard_timeout,
                };
            }
            Err(err) => {
                self.status = Status::Info(format!("copy failed: {err}"));
            }
        }
    }

    fn lock(&mut self) {
        // Clear any copied secret immediately on lock.
        self.clear_clipboard_guard();
        // Drop the write handle, the cloud session and the session key
        // (zeroized on drop).
        self.handle = None;
        self.key = None;
        self.cloud = None;
        self.pending = None;
        self.busy = None;
        self.conflict = None;
        self.consent = None;
        self.state.lock();
        self.status = Status::Idle;
        self.unlock = UnlockInput::default();
        self.unlock_error = None;
    }
}

/// The user plugin directory (`$HOME/.config/kpd/plugins`).
fn plugins_dir() -> std::path::PathBuf {
    match std::env::var("HOME") {
        Ok(home) => std::path::PathBuf::from(home).join(".config/kpd/plugins"),
        Err(_) => std::path::PathBuf::from("plugins"),
    }
}

fn plugins_dir_hint() -> String {
    format!("{} or ./plugins", plugins_dir().display())
}

/// Every `.wasm` in `./plugins` and the user plugin dir (sorted, deduped).
fn discover_plugins() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for dir in [std::path::PathBuf::from("plugins"), plugins_dir()] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("wasm") {
                out.push(path);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    use keepass::db::fields;
    use keepass::{Database as KpDatabase, DatabaseKey};
    use secrecy::ExposeSecret;

    const PASSWORD: &str = "test master password";

    /// A throwaway directory removed on drop (the storage write lock and any
    /// temp files live inside it).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let dir =
                std::env::temp_dir().join(format!("kpd-tui-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn db_path(&self) -> PathBuf {
            self.0.join("db.kdbx")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Write a real KDBX file with one password-protected entry per title.
    fn seed_db(path: &Path, titles: &[&str]) {
        let mut db = KpDatabase::new();
        {
            let mut root = db.root_mut();
            for title in titles {
                let mut entry = root.add_entry();
                entry.set_unprotected(fields::TITLE, *title);
                entry.set_protected(fields::PASSWORD, "hunter2");
            }
        }
        let mut file = fs::File::create(path).expect("create seed db");
        db.save(&mut file, DatabaseKey::new().with_password(PASSWORD))
            .expect("seed save");
    }

    fn cloud_app(path: &Path) -> App {
        App::new(AppConfig::cloud(kpd_storage::BackendSpec::Local {
            path: path.to_path_buf(),
        }))
    }

    /// Deliver one key press and run any deferred cloud work it queued.
    fn press(app: &mut App, code: KeyCode) {
        app.handle_key(&KeyEvent::new(code, KeyModifiers::NONE));
        if app.is_busy() {
            app.run_pending();
        }
    }

    fn press_ctrl(app: &mut App, c: char) {
        app.handle_key(&KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
        if app.is_busy() {
            app.run_pending();
        }
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    /// Replace the edit prompt's prefilled value with `text`.
    fn replace_input(app: &mut App, text: &str) {
        while !app.state.input.is_empty() {
            press(app, KeyCode::Backspace);
        }
        type_text(app, text);
    }

    fn unlock(app: &mut App, password: &str) {
        type_text(app, password);
        press(app, KeyCode::Enter);
    }

    fn info(app: &App) -> String {
        match app.status() {
            Status::Info(message) => message.clone(),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn plugin_consent_lists_manifest_capabilities_and_grants_them() {
        let dir = TempDir::new("plugin-consent");
        let wasm = dir.0.join("demo.wasm");
        fs::write(&wasm, b"not a component").expect("write wasm placeholder");
        fs::write(
            dir.0.join("demo.toml"),
            "name = \"demo\"\ndescription = \"demo plugin\"\ncapabilities = [\"entries.read\"]\n",
        )
        .expect("write manifest");

        let mut app = App::new(AppConfig::new(dir.0.join("unused.kdbx")));
        let menu = || crate::state::PluginMenu {
            paths: vec![wasm.clone()],
            index: 0,
        };

        app.state.plugin_menu = Some(menu());
        press(&mut app, KeyCode::Enter);

        let consent = app.consent().expect("consent prompt");
        assert_eq!(consent.name, "demo");
        assert_eq!(consent.capabilities, vec![Permission::EntriesRead]);
        assert!(app.key_tips().contains(&("Y", "Allow")));

        // Declining leaves no prompt behind.
        press(&mut app, KeyCode::Char('n'));
        assert!(app.consent().is_none());
        assert_eq!(app.state.prompt, Prompt::None);

        // Approving proceeds to the command prompt with the declared grants.
        app.state.plugin_menu = Some(menu());
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('y'));
        match &app.state.prompt {
            Prompt::PluginCommand {
                wasm: path,
                permissions,
            } => {
                assert_eq!(path, &wasm);
                assert_eq!(permissions, &vec![Permission::EntriesRead]);
            }
            other => panic!("expected a plugin command prompt, got {other:?}"),
        }
    }

    #[test]
    fn plugin_without_a_manifest_is_refused() {
        let dir = TempDir::new("plugin-no-manifest");
        let wasm = dir.0.join("demo.wasm");
        fs::write(&wasm, b"not a component").expect("write wasm placeholder");

        let mut app = App::new(AppConfig::new(dir.0.join("unused.kdbx")));
        app.state.plugin_menu = Some(crate::state::PluginMenu {
            paths: vec![wasm],
            index: 0,
        });
        press(&mut app, KeyCode::Enter);

        assert!(app.consent().is_none());
        assert!(info(&app).contains("manifest"), "{}", info(&app));
        assert_eq!(app.state.prompt, Prompt::None);
    }

    #[test]
    fn key_tips_follow_the_active_screen() {
        let dir = TempDir::new("tips-screen");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = App::new(AppConfig::new(&path));
        assert_eq!(app.key_tips(), vec![("Enter", "Unlock"), ("Esc", "Quit")]);

        unlock(&mut app, PASSWORD);
        assert!(app.key_tips().contains(&("P", "Plugins")));
        assert!(app.key_tips().contains(&("^S", "Save")));

        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Enter);
        assert!(app.key_tips().contains(&("Esc", "Back")));
        assert!(app.key_tips().contains(&("R", "Reveal")));
    }

    #[test]
    fn key_tips_follow_prompts_and_conflicts() {
        let dir = TempDir::new("tips-modal");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = cloud_app(&path);
        unlock(&mut app, PASSWORD);

        // A text prompt asks for submit/cancel.
        press(&mut app, KeyCode::Char('e'));
        assert!(app.key_tips().contains(&("Enter", "Submit")));
        press(&mut app, KeyCode::Esc);

        // A save conflict exposes the two resolutions.
        seed_db(&path, &["Alpha", "Beta"]);
        press(&mut app, KeyCode::Char('e'));
        replace_input(&mut app, "local-edit");
        press(&mut app, KeyCode::Enter);
        press_ctrl(&mut app, 's');
        press(&mut app, KeyCode::Char('y'));

        assert_eq!(app.key_tips()[0], ("R", "Reload remote"));
        assert_eq!(app.key_tips()[1], ("O", "Overwrite remote"));
        assert_eq!(app.key_tips()[2], ("Esc", "Dismiss"));
    }

    #[test]
    fn cloud_unlock_fetches_and_save_upload_with_revision() {
        let dir = TempDir::new("cloud-save");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = cloud_app(&path);
        unlock(&mut app, PASSWORD);
        assert_eq!(app.unlock_error(), None);
        assert!(app.state.db.is_some(), "cloud unlock should browse the db");
        assert!(info(&app).starts_with("loaded "), "{}", info(&app));

        // Edit the selected entry's password, then save through the backend.
        press(&mut app, KeyCode::Char('e'));
        replace_input(&mut app, "new-password");
        press(&mut app, KeyCode::Enter);
        press_ctrl(&mut app, 's');
        press(&mut app, KeyCode::Char('y'));
        assert!(info(&app).contains("saved"), "{}", info(&app));

        // The remote file really changed and reopens to the edited password.
        let key = CompositeKey::new().with_password(PASSWORD);
        let reopened = DbHandle::open(&path, &key).expect("reopen remote db");
        let view = reopened.view();
        assert_eq!(
            view.root.entries[0].password.expose_secret(),
            "new-password"
        );

        // The session revision was refreshed, so a second save does not conflict.
        press_ctrl(&mut app, 's');
        press(&mut app, KeyCode::Char('y'));
        assert!(info(&app).contains("saved"), "second save: {}", info(&app));
    }

    #[test]
    fn cloud_save_conflict_leaves_the_remote_untouched() {
        let dir = TempDir::new("cloud-conflict");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = cloud_app(&path);
        unlock(&mut app, PASSWORD);
        assert_eq!(app.unlock_error(), None);

        // Somebody else changes the remote after this session was opened.
        seed_db(&path, &["Alpha", "Beta"]);
        let remote_after_change = fs::read(&path).expect("read changed remote");

        press(&mut app, KeyCode::Char('e'));
        replace_input(&mut app, "local-edit");
        press(&mut app, KeyCode::Enter);
        press_ctrl(&mut app, 's');
        press(&mut app, KeyCode::Char('y'));

        assert_eq!(
            app.conflict_label(),
            Some("db.kdbx"),
            "expected the conflict modal, got status: {}",
            info(&app)
        );
        assert!(info(&app).contains("conflict"));

        // The remote bytes are exactly what the other writer left.
        let remote_now = fs::read(&path).expect("read remote after refused save");
        assert_eq!(remote_now, remote_after_change);
    }

    #[test]
    fn conflict_reload_replaces_the_database_and_discards_local_edits() {
        let dir = TempDir::new("conflict-reload");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = cloud_app(&path);
        unlock(&mut app, PASSWORD);
        assert_eq!(app.unlock_error(), None);

        // A concurrent writer replaces the remote with two entries.
        seed_db(&path, &["Alpha", "Beta"]);

        // Local edit that must be thrown away by the reload.
        press(&mut app, KeyCode::Char('e'));
        replace_input(&mut app, "local-edit");
        press(&mut app, KeyCode::Enter);
        press_ctrl(&mut app, 's');
        press(&mut app, KeyCode::Char('y'));
        assert!(app.conflict_label().is_some());

        press(&mut app, KeyCode::Char('r'));

        assert!(
            app.conflict_label().is_none(),
            "reload should clear the conflict"
        );
        let status = info(&app);
        assert!(status.contains("reloaded"), "{status}");
        let key = CompositeKey::new().with_password(PASSWORD);
        let reopened = DbHandle::open(&path, &key).expect("reopen remote");
        assert_eq!(app.state.entry_count(), reopened.view().root.entries.len());
        assert_eq!(
            app.state.entry_count(),
            2,
            "reload must adopt the remote state"
        );
        let db = app.state.db.as_ref().expect("unlocked after reload");
        assert_eq!(db.root.entries[1].title, "Beta");
        // The discarded edit did not leak into the reloaded view.
        assert_eq!(db.root.entries[0].password.expose_secret(), "hunter2");
    }

    #[test]
    fn conflict_overwrite_keeps_local_edits_and_forces_the_remote() {
        let dir = TempDir::new("conflict-overwrite");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = cloud_app(&path);
        unlock(&mut app, PASSWORD);
        assert_eq!(app.unlock_error(), None);

        // A concurrent writer changes the remote after unlock.
        seed_db(&path, &["Alpha", "Beta"]);

        press(&mut app, KeyCode::Char('e'));
        replace_input(&mut app, "local-edit");
        press(&mut app, KeyCode::Enter);
        press_ctrl(&mut app, 's');
        press(&mut app, KeyCode::Char('y'));
        assert!(app.conflict_label().is_some());

        // O forces the upload with the local edits, discarding the remote state.
        press(&mut app, KeyCode::Char('o'));

        assert!(app.conflict_label().is_none());
        let status = info(&app);
        assert!(status.contains("saved"), "{status}");
        assert!(status.contains("overwrote remote"), "{status}");

        let key = CompositeKey::new().with_password(PASSWORD);
        let reopened = DbHandle::open(&path, &key).expect("reopen remote");
        let view = reopened.view();
        assert_eq!(view.root.entries.len(), 1);
        assert_eq!(view.root.entries[0].title, "Alpha");
        assert_eq!(view.root.entries[0].password.expose_secret(), "local-edit");
    }

    #[test]
    fn cloud_unlock_reports_wrong_password_and_stays_locked() {
        let dir = TempDir::new("cloud-bad-password");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = cloud_app(&path);
        unlock(&mut app, "not the password");

        assert!(app.state.db.is_none(), "a bad password must not unlock");
        assert!(
            app.unlock_error()
                .is_some_and(|err| err.contains("wrong master password")),
            "{:?}",
            app.unlock_error()
        );
        assert!(!app.is_busy());
    }

    #[test]
    fn cloud_unlock_rejects_an_invalid_backend_before_fetching() {
        let mut app = App::new(AppConfig::cloud(kpd_storage::BackendSpec::WebDav {
            url: "ftp://example.com/db.kdbx".to_string(),
            username: None,
            password: None,
        }));

        unlock(&mut app, PASSWORD);

        assert!(!app.is_busy(), "invalid config must not queue a fetch");
        assert!(app.state.db.is_none());
        assert!(
            app.unlock_error()
                .is_some_and(|err| err.contains("unsupported WebDAV URL scheme")),
            "{:?}",
            app.unlock_error()
        );
    }

    #[test]
    fn local_unlock_still_uses_the_file_save_path() {
        let dir = TempDir::new("local-save");
        let path = dir.db_path();
        seed_db(&path, &["Alpha"]);

        let mut app = App::new(AppConfig::new(&path));
        unlock(&mut app, PASSWORD);
        assert_eq!(app.unlock_error(), None);

        press(&mut app, KeyCode::Char('e'));
        replace_input(&mut app, "local-password");
        press(&mut app, KeyCode::Enter);
        press_ctrl(&mut app, 's');
        press(&mut app, KeyCode::Char('y'));

        let status = info(&app);
        assert!(status.contains("saved"), "{status}");
        assert!(status.contains("backup written"), "{status}");
    }
}
