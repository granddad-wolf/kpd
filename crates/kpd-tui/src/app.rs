//! Runtime application state and key handling: the terminal-aware glue that
//! connects the pure [`state::State`] machine to crossterm key events, the
//! clipboard, and the unlock flow. Secrets are held only where the `State`
//! machine or [`ClipboardGuard`] already owns them.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use kpd_clipboard::{copy_autoclear, ClipboardGuard};
use kpd_crypto::CompositeKey;
use kpd_kdbx::{DbHandle, EntryField, SaveOptions};

use crate::state::{AddEntryOutcome, Move, Prompt, Screen, State};
use crate::AppConfig;

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

        match DbHandle::open(&self.config.db_path, &key) {
            Ok(handle) => {
                let view = handle.view();
                self.unlock_error = None;
                self.handle = Some(handle);
                self.key = Some(key);
                self.state.unlock(view);
                self.status = Status::Idle;
            }
            Err(err) => {
                // `key` drops here (zeroized); force re-entry on failure.
                self.unlock_error = Some(err.to_string());
                self.unlock = UnlockInput::default();
            }
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
        // Drop the write handle and the session key (zeroized on drop).
        self.handle = None;
        self.key = None;
        self.state.lock();
        self.status = Status::Idle;
        self.unlock = UnlockInput::default();
        self.unlock_error = None;
    }
}
