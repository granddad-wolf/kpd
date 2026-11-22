//! Runtime application state and key handling: the terminal-aware glue that
//! connects the pure [`state::State`] machine to crossterm key events, the
//! clipboard, and the unlock flow (local file or cloud storage). Secrets are
//! held only where the `State` machine or [`ClipboardGuard`] already owns them.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use kpd_clipboard::{copy_autoclear, ClipboardGuard};
use kpd_crypto::CompositeKey;
use kpd_kdbx::{DbHandle, EntryField, SaveOptions};
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
    /// the save is the one that promoted the database to KDBX 4.1.
    Save { upgraded: bool },
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
            Pending::Save { upgraded } => self.save_cloud(upgraded),
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
                    self.state.begin_plugin_command(wasm);
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
            Prompt::PluginCommand { wasm } => {
                let command_line = std::mem::take(&mut self.state.input);
                self.run_plugin(&wasm, &command_line);
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
    fn run_plugin(&mut self, wasm: &std::path::Path, command_line: &str) {
        use kpd_plugin_runtime::{EntrySummary, Limits, Permission, PluginRuntime, RunContext};

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
        let permissions = [Permission::EntriesRead, Permission::ClipboardWrite];
        let mut plugin = match runtime.load(wasm, &permissions, Limits::default()) {
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
            self.busy = Some(format!("saving to {}", self.config.location.short_label()));
            self.pending = Some(Pending::Save { upgraded });
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

    /// Serialize the in-memory database and upload it with the revision the
    /// session was opened at. A revision mismatch surfaces as a conflict and
    /// leaves the remote untouched.
    fn save_cloud(&mut self, upgraded: bool) {
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
        match runtime.block_on(cloud.storage.write(&bytes, cloud.revision.as_deref())) {
            Ok(meta) => {
                cloud.revision = meta.revision;
                let mut msg = format!("saved {} bytes to {}", bytes.len(), label);
                if upgraded {
                    msg.push_str(" — upgraded to KDBX 4.1");
                }
                self.status = Status::Info(msg);
            }
            Err(StorageError::Conflict(detail)) => {
                let reason = if detail.contains("locked") {
                    "is locked by another client — try again shortly"
                } else {
                    "changed remotely — L then unlock to reload (edits kept)"
                };
                self.status = Status::Info(format!("conflict: {label} {reason}"));
            }
            Err(err) => self.status = Status::Info(format!("save failed: {err}")),
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

        let status = info(&app);
        assert!(
            status.contains("conflict"),
            "expected conflict, got: {status}"
        );

        // The remote bytes are exactly what the other writer left.
        let remote_now = fs::read(&path).expect("read remote after refused save");
        assert_eq!(remote_now, remote_after_change);
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
