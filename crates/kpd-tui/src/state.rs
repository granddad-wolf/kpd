//! Pure, terminal-independent application state: selection, navigation, search,
//! detail data, lock/unlock transitions, and the prompt model for
//! create/edit/delete/save.
//!
//! This module has no I/O and depends only on `kpd-core`, `secrecy`, `uuid`, and
//! the pure `kpd_kdbx::EntryField` enum, so its logic is unit-testable without a
//! terminal. Secrets are held as [`SecretString`]; they are exposed to plain
//! `String`s only by the clipboard copy path (see [`State::secret_to_copy`]) and
//! when seeding an edit-prompt buffer (see [`State::field_value`]).

use kpd_core::db::{Database, Entry, EntryRef, Group};
use kpd_kdbx::EntryField;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

/// The screen currently shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Unlock,
    Browse,
    Detail,
}

/// Which pane owns `↑`/`↓` navigation while browsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Focus {
    #[default]
    Groups,
    Entries,
}

/// A movement direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Move {
    Up,
    Down,
}

/// A flattened node of the group tree (pre-order), for the left pane.
#[derive(Debug, Clone)]
pub struct GroupNode {
    pub uuid: Uuid,
    pub name: String,
    /// Nesting depth; the root group is depth 0.
    pub depth: usize,
    /// Group names from the root down to (but excluding) this group, matching
    /// [`EntryRef::group_path`] semantics (the root's own name is excluded).
    pub path: Vec<String>,
}

/// A display row in the detail view.
#[derive(Debug, Clone)]
pub struct DetailRow {
    pub label: String,
    pub value: DetailValue,
    /// Whether `Ctrl+C` can copy this row (attachments cannot be copied).
    pub copyable: bool,
}

/// A detail value. Secrets are masked unless reveal is toggled on.
#[derive(Debug, Clone)]
pub enum DetailValue {
    Text(String),
    Secret(SecretString),
}

/// An in-progress create/edit/delete/save prompt.
///
/// `None` means no prompt is active. The text prompts drive the `input` buffer
/// (masked per [`State::masked_input`]); the `Confirm*` prompts are yes/no and
/// ignore `input`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Prompt {
    #[default]
    None,
    AddEntryTitle,
    AddEntryUsername {
        title: String,
    },
    AddEntryPassword {
        title: String,
        username: String,
    },
    AddGroupName,
    EditField {
        entry_uuid: Uuid,
        field: EntryField,
    },
    ConfirmDeleteEntry {
        entry_uuid: Uuid,
    },
    ConfirmDeleteGroup {
        group_uuid: Uuid,
    },
    ConfirmSave,
}

/// Progress of the multi-step add-entry flow after one `Enter` commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddEntryOutcome {
    /// The prompt advanced to the next step; more input is required.
    Continue,
    /// Title, username, and password are all captured; the caller performs the
    /// `DbHandle::add_entry` mutation with these values.
    Complete {
        title: String,
        username: String,
        password: String,
    },
}

/// Pure application state. `db` is `None` while locked.
pub struct State {
    /// The unlocked database; `None` while on the unlock screen.
    pub db: Option<Database>,
    pub screen: Screen,
    pub focus: Focus,
    /// Index into [`State::group_nodes`].
    pub group_index: usize,
    /// Index into [`State::entry_refs`] (the currently displayed entry list).
    pub entry_index: usize,
    /// Active search query; empty means "no filter".
    pub search_query: String,
    /// True while the user is typing a search query (`Ctrl+F` mode).
    pub searching: bool,
    /// Entry shown in the detail view; `None` outside the detail view.
    pub detail_uuid: Option<Uuid>,
    /// Index into [`State::detail_rows`].
    pub detail_index: usize,
    /// Reveal masked secret values (password, custom-field values) in detail.
    pub reveal_secrets: bool,
    /// The active create/edit/delete/save prompt.
    pub prompt: Prompt,
    /// Text buffer for the active prompt.
    pub input: String,
    /// Whether `input` is a secret and must be rendered masked.
    pub masked_input: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            db: None,
            screen: Screen::Unlock,
            focus: Focus::Groups,
            group_index: 0,
            entry_index: 0,
            search_query: String::new(),
            searching: false,
            detail_uuid: None,
            detail_index: 0,
            reveal_secrets: false,
            prompt: Prompt::None,
            input: String::new(),
            masked_input: false,
        }
    }
}

impl State {
    /// Flatten the group tree (root included) into pre-order nodes.
    pub fn group_nodes(&self) -> Vec<GroupNode> {
        let mut out = Vec::new();
        if let Some(db) = &self.db {
            collect_groups(&db.root, 0, &mut Vec::new(), &mut out);
        }
        out
    }

    /// The entry list currently shown in the right pane: search results when a
    /// query is active, otherwise the selected group's entries.
    pub fn entry_refs(&self) -> Vec<EntryRef> {
        let Some(db) = &self.db else {
            return Vec::new();
        };
        if !self.search_query.is_empty() {
            return db.search(&self.search_query);
        }
        let nodes = self.group_nodes();
        let Some(node) = nodes.get(self.group_index) else {
            return Vec::new();
        };
        let Some(group) = db.group_by_uuid(node.uuid) else {
            return Vec::new();
        };
        group
            .entries
            .iter()
            .map(|e| EntryRef {
                group_path: node.path.clone(),
                entry_uuid: e.uuid,
            })
            .collect()
    }

    /// The currently selected entry (by [`State::entry_index`]).
    pub fn selected_entry(&self) -> Option<&Entry> {
        let uuid = self.entry_refs().get(self.entry_index)?.entry_uuid;
        self.db.as_ref()?.entry(uuid)
    }

    /// The entry shown in the detail view.
    pub fn detail_entry(&self) -> Option<&Entry> {
        let uuid = self.detail_uuid?;
        self.db.as_ref()?.entry(uuid)
    }

    /// The ordered rows of the detail view for the currently open entry.
    pub fn detail_rows(&self) -> Vec<DetailRow> {
        match self.detail_entry() {
            Some(entry) => detail_rows_for(entry),
            None => Vec::new(),
        }
    }

    /// Total number of entries in the unlocked database.
    pub fn entry_count(&self) -> usize {
        self.db
            .as_ref()
            .map(|db| db.all_entries().len())
            .unwrap_or(0)
    }

    /// Move the selection in the focused pane.
    pub fn navigate(&mut self, direction: Move) {
        match self.focus {
            Focus::Groups => self.move_group(direction),
            Focus::Entries => self.move_entry(direction),
        }
    }

    /// Switch focus between the group and entry panes (`Tab`).
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Groups => Focus::Entries,
            Focus::Entries => Focus::Groups,
        };
    }

    /// Open the selected entry in the detail view (no-op if none is selected).
    pub fn open_selected(&mut self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let uuid = entry.uuid;
        let rows = detail_rows_for(entry);
        let index = rows
            .iter()
            .position(|row| matches!(row.value, DetailValue::Secret(_)))
            .unwrap_or(0);
        self.detail_uuid = Some(uuid);
        self.detail_index = index;
        self.reveal_secrets = false;
        self.screen = Screen::Detail;
    }

    /// Close the detail view and return to browsing.
    pub fn close_detail(&mut self) {
        self.screen = Screen::Browse;
        self.detail_uuid = None;
        self.reveal_secrets = false;
    }

    /// Enter search-input mode.
    pub fn begin_search(&mut self) {
        self.searching = true;
        self.focus = Focus::Entries;
        self.entry_index = 0;
    }

    /// Append a character to the active search query.
    pub fn type_search(&mut self, c: char) {
        if self.searching {
            self.search_query.push(c);
            self.entry_index = 0;
        }
    }

    /// Remove the last character of the active search query.
    pub fn backspace_search(&mut self) {
        if self.searching {
            self.search_query.pop();
            self.entry_index = 0;
        }
    }

    /// Leave search-input mode but keep the current filter applied.
    pub fn commit_search(&mut self) {
        self.searching = false;
    }

    /// Clear the search query and leave search-input mode.
    pub fn cancel_search(&mut self) {
        self.search_query.clear();
        self.searching = false;
        self.entry_index = 0;
    }

    /// Move the focused field in the detail view.
    pub fn detail_navigate(&mut self, direction: Move) {
        let len = self.detail_rows().len();
        if len == 0 {
            self.detail_index = 0;
            return;
        }
        self.detail_index = match direction {
            Move::Up => self.detail_index.saturating_sub(1),
            Move::Down => (self.detail_index + 1).min(len - 1),
        };
    }

    /// Toggle reveal of masked secret values in the detail view.
    pub fn toggle_reveal(&mut self) {
        self.reveal_secrets = !self.reveal_secrets;
    }

    /// The secret to copy for the current context: the selected entry's
    /// password while browsing, or the focused detail row's value in detail.
    pub fn secret_to_copy(&self) -> Option<SecretString> {
        match self.screen {
            Screen::Unlock => None,
            Screen::Browse => self.selected_entry().map(|e| e.password.clone()),
            Screen::Detail => {
                let entry = self.detail_entry()?;
                let row = detail_rows_for(entry).get(self.detail_index)?.clone();
                if !row.copyable {
                    return None;
                }
                match row.value {
                    DetailValue::Text(text) => Some(SecretString::from(text)),
                    DetailValue::Secret(secret) => Some(secret),
                }
            }
        }
    }

    /// Drop the in-memory database and return to the unlock screen.
    pub fn lock(&mut self) {
        *self = State::default();
    }

    /// Store the freshly decrypted database and enter the browse screen.
    pub fn unlock(&mut self, db: Database) {
        self.db = Some(db);
        self.screen = Screen::Browse;
        self.focus = Focus::Groups;
        self.group_index = 0;
        self.entry_index = 0;
        self.search_query.clear();
        self.searching = false;
        self.detail_uuid = None;
        self.detail_index = 0;
        self.reveal_secrets = false;
    }

    /// Replace the database view after a mutation WITHOUT resetting selection;
    /// clamp `group_index` / `entry_index` / `detail_index` to the new bounds.
    pub fn replace_db(&mut self, db: Database) {
        self.db = Some(db);

        let group_len = self.group_nodes().len();
        self.group_index = self.group_index.min(group_len.saturating_sub(1));

        let entry_len = self.entry_refs().len();
        self.entry_index = self.entry_index.min(entry_len.saturating_sub(1));

        let detail_len = self.detail_rows().len();
        self.detail_index = self.detail_index.min(detail_len.saturating_sub(1));
    }

    /// The currently selected group's UUID (the target for add entry/group).
    /// Returns `None` while locked or when no group is selected.
    pub fn selected_group_uuid(&self) -> Option<Uuid> {
        self.group_nodes()
            .get(self.group_index)
            .map(|node| node.uuid)
    }

    /// Append a character to the active prompt's input buffer.
    pub fn type_input(&mut self, c: char) {
        self.input.push(c);
    }

    /// Remove the last character of the active prompt's input buffer.
    pub fn backspace_input(&mut self) {
        self.input.pop();
    }

    /// Begin the multi-step add-entry flow (title → username → password).
    pub fn begin_add_entry(&mut self) {
        self.prompt = Prompt::AddEntryTitle;
        self.input.clear();
        self.masked_input = false;
    }

    /// Begin the add-group prompt.
    pub fn begin_add_group(&mut self) {
        self.prompt = Prompt::AddGroupName;
        self.input.clear();
        self.masked_input = false;
    }

    /// Begin an edit prompt for one field of an entry, prefilling the buffer
    /// with the field's current value (secrets are exposed only long enough to
    /// seed the buffer and are still masked while typing).
    pub fn begin_edit_field(&mut self, entry_uuid: Uuid, field: EntryField) {
        self.input = self.field_value(entry_uuid, &field).unwrap_or_default();
        self.masked_input = field_is_secret(&field);
        self.prompt = Prompt::EditField { entry_uuid, field };
    }

    /// Begin the delete-entry confirmation.
    pub fn begin_confirm_delete_entry(&mut self, entry_uuid: Uuid) {
        self.prompt = Prompt::ConfirmDeleteEntry { entry_uuid };
        self.input.clear();
        self.masked_input = false;
    }

    /// Begin the delete-group confirmation.
    pub fn begin_confirm_delete_group(&mut self, group_uuid: Uuid) {
        self.prompt = Prompt::ConfirmDeleteGroup { group_uuid };
        self.input.clear();
        self.masked_input = false;
    }

    /// Begin the save confirmation.
    pub fn begin_confirm_save(&mut self) {
        self.prompt = Prompt::ConfirmSave;
        self.input.clear();
        self.masked_input = false;
    }

    /// Commit the current add-entry prompt step, capturing `input` into the
    /// accumulated title/username/password and advancing to the next step. On
    /// the final step the flow completes and the caller performs the mutation.
    pub fn commit_add_entry(&mut self) -> AddEntryOutcome {
        let previous = std::mem::take(&mut self.prompt);
        match previous {
            Prompt::AddEntryTitle => {
                let title = std::mem::take(&mut self.input);
                self.prompt = Prompt::AddEntryUsername { title };
                self.masked_input = false;
                AddEntryOutcome::Continue
            }
            Prompt::AddEntryUsername { title } => {
                let username = std::mem::take(&mut self.input);
                self.prompt = Prompt::AddEntryPassword { title, username };
                self.masked_input = true;
                AddEntryOutcome::Continue
            }
            Prompt::AddEntryPassword { title, username } => {
                let password = std::mem::take(&mut self.input);
                self.prompt = Prompt::None;
                self.masked_input = false;
                AddEntryOutcome::Complete {
                    title,
                    username,
                    password,
                }
            }
            other => {
                self.prompt = other;
                AddEntryOutcome::Continue
            }
        }
    }

    /// Cancel the active prompt: clear it, its buffer, and the mask flag.
    pub fn cancel_prompt(&mut self) {
        self.prompt = Prompt::None;
        self.input.clear();
        self.masked_input = false;
    }

    /// The editable [`EntryField`] for the currently focused detail row, if the
    /// row maps to a standard editable field (custom fields and attachments are
    /// not editable from the detail view).
    pub fn detail_edit_field(&self) -> Option<EntryField> {
        let entry = self.detail_entry()?;
        detail_edit_field_for(entry, self.detail_index)
    }

    /// The current plaintext value of `field` for `entry_uuid`, used to prefill
    /// an edit buffer. Secret values are exposed only here and only long enough
    /// to seed the buffer.
    pub fn field_value(&self, entry_uuid: Uuid, field: &EntryField) -> Option<String> {
        let entry = self.db.as_ref()?.entry(entry_uuid)?;
        Some(match field {
            EntryField::Title => entry.title.clone(),
            EntryField::UserName => entry.username.clone(),
            EntryField::Password => entry.password.expose_secret().to_string(),
            EntryField::Url => entry.url.clone().unwrap_or_default(),
            EntryField::Notes => entry.notes.clone().unwrap_or_default(),
            EntryField::Custom(key) => entry
                .custom_fields
                .iter()
                .find(|field| &field.key == key)
                .map(|field| field.value.expose_secret().to_string())
                .unwrap_or_default(),
        })
    }

    fn move_group(&mut self, direction: Move) {
        let len = self.group_nodes().len();
        if len == 0 {
            return;
        }
        self.group_index = match direction {
            Move::Up => self.group_index.saturating_sub(1),
            Move::Down => (self.group_index + 1).min(len - 1),
        };
        self.entry_index = 0;
    }

    fn move_entry(&mut self, direction: Move) {
        let len = self.entry_refs().len();
        if len == 0 {
            self.entry_index = 0;
            return;
        }
        self.entry_index = match direction {
            Move::Up => self.entry_index.saturating_sub(1),
            Move::Down => (self.entry_index + 1).min(len - 1),
        };
    }
}

/// Depth-first, pre-order flatten. `path` accumulates group names from the root
/// down to (but excluding) the group currently being visited.
fn collect_groups(group: &Group, depth: usize, path: &mut Vec<String>, out: &mut Vec<GroupNode>) {
    out.push(GroupNode {
        uuid: group.uuid,
        name: group.name.clone(),
        depth,
        path: path.clone(),
    });
    for child in &group.children {
        path.push(child.name.clone());
        collect_groups(child, depth + 1, path, out);
        path.pop();
    }
}

/// Build the ordered detail rows for an entry. The password row is the first
/// [`DetailValue::Secret`], so it becomes the default focus.
fn detail_rows_for(entry: &Entry) -> Vec<DetailRow> {
    let mut rows = Vec::new();
    rows.push(DetailRow {
        label: "Title".to_string(),
        value: DetailValue::Text(entry.title.clone()),
        copyable: false,
    });
    rows.push(DetailRow {
        label: "Username".to_string(),
        value: DetailValue::Text(entry.username.clone()),
        copyable: true,
    });
    rows.push(DetailRow {
        label: "Password".to_string(),
        value: DetailValue::Secret(entry.password.clone()),
        copyable: true,
    });
    if let Some(url) = &entry.url {
        rows.push(DetailRow {
            label: "URL".to_string(),
            value: DetailValue::Text(url.clone()),
            copyable: true,
        });
    }
    if let Some(notes) = &entry.notes {
        rows.push(DetailRow {
            label: "Notes".to_string(),
            value: DetailValue::Text(notes.clone()),
            copyable: true,
        });
    }
    for field in &entry.custom_fields {
        rows.push(DetailRow {
            label: format!("Custom: {}", field.key),
            value: DetailValue::Secret(field.value.clone()),
            copyable: true,
        });
    }
    for attachment in &entry.attachments {
        rows.push(DetailRow {
            label: "Attachment".to_string(),
            value: DetailValue::Text(attachment.name.clone()),
            copyable: false,
        });
    }
    rows
}

/// Whether an [`EntryField`] holds secret material (and thus must be masked).
fn field_is_secret(field: &EntryField) -> bool {
    matches!(field, EntryField::Password | EntryField::Custom(_))
}

/// Map a detail-row index to the editable standard field it represents, or
/// `None` when the row is not editable (custom fields and attachments).
///
/// This mirrors the row order produced by [`detail_rows_for`] and must be kept
/// in sync with it.
fn detail_edit_field_for(entry: &Entry, index: usize) -> Option<EntryField> {
    let mut row = 0usize;

    // Title
    if row == index {
        return Some(EntryField::Title);
    }
    row += 1;
    // Username
    if row == index {
        return Some(EntryField::UserName);
    }
    row += 1;
    // Password
    if row == index {
        return Some(EntryField::Password);
    }
    row += 1;
    // URL (only present when set)
    if entry.url.is_some() {
        if row == index {
            return Some(EntryField::Url);
        }
        row += 1;
    }
    // Notes (only present when set)
    if entry.notes.is_some() {
        if row == index {
            return Some(EntryField::Notes);
        }
    }

    // Remaining rows are custom fields and attachments, which are not editable.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use kpd_core::db::{Database, Entry, Group};
    use secrecy::{ExposeSecret, SecretString};
    use uuid::Uuid;

    fn uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn entry(id: u128, title: &str, username: &str) -> Entry {
        Entry {
            uuid: uuid(id),
            title: title.to_string(),
            username: username.to_string(),
            password: SecretString::from("pw".to_string()),
            ..Default::default()
        }
    }

    fn group(id: u128, name: &str) -> Group {
        Group {
            uuid: uuid(id),
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Root has one entry (GitHub); Work has Email and Slack; Work's child
    /// Projects has AWS.
    fn sample_db() -> Database {
        let mut root = group(0x1000, "Root");
        root.entries.push(entry(0xE1, "GitHub", "octocat"));

        let mut work = group(0x1001, "Work");
        work.entries.push(entry(0xE2, "Email", "alice@corp"));
        work.entries.push(entry(0xE4, "Slack", "alice"));

        let mut projects = group(0x1002, "Projects");
        projects.entries.push(entry(0xE3, "AWS", "alice"));
        work.children.push(projects);

        root.children.push(work);
        Database {
            root,
            name: None,
            generator: None,
        }
    }

    fn unlocked(db: Database) -> State {
        State {
            db: Some(db),
            screen: Screen::Browse,
            ..State::default()
        }
    }

    #[test]
    fn defaults_to_unlock_and_locked() {
        let s = State::default();
        assert_eq!(s.screen, Screen::Unlock);
        assert!(s.db.is_none());
        assert_eq!(s.entry_count(), 0);
    }

    #[test]
    fn group_nodes_are_flattened_preorder_with_paths() {
        let s = unlocked(sample_db());
        let nodes = s.group_nodes();
        let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["Root", "Work", "Projects"]);
        assert_eq!(nodes[0].depth, 0);
        assert_eq!(nodes[1].depth, 1);
        assert_eq!(nodes[2].depth, 2);
        assert!(nodes[0].path.is_empty());
        assert_eq!(&nodes[1].path, &vec!["Work".to_string()]);
        assert_eq!(
            &nodes[2].path,
            &vec!["Work".to_string(), "Projects".to_string()]
        );
    }

    #[test]
    fn entry_refs_show_selected_group() {
        let mut s = unlocked(sample_db());
        s.group_index = 1; // Work
        let refs = s.entry_refs();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].entry_uuid, uuid(0xE2));
        assert_eq!(&refs[0].group_path, &vec!["Work".to_string()]);
    }

    #[test]
    fn navigate_entries_clamps_selection_bounds() {
        let mut s = unlocked(sample_db());
        s.focus = Focus::Entries;
        s.group_index = 1; // Work: 2 entries
        assert_eq!(s.entry_index, 0);
        s.navigate(Move::Down);
        assert_eq!(s.entry_index, 1);
        s.navigate(Move::Down); // clamped
        assert_eq!(s.entry_index, 1);
        s.navigate(Move::Up);
        assert_eq!(s.entry_index, 0);
        s.navigate(Move::Up); // clamped
        assert_eq!(s.entry_index, 0);
    }

    #[test]
    fn navigate_groups_resets_entry_selection() {
        let mut s = unlocked(sample_db());
        s.group_index = 1;
        s.focus = Focus::Entries;
        s.navigate(Move::Down); // entry 0 -> 1
        assert_eq!(s.entry_index, 1);
        s.focus = Focus::Groups;
        s.navigate(Move::Down); // group 1 -> 2
        assert_eq!(s.group_index, 2);
        assert_eq!(s.entry_index, 0);
    }

    #[test]
    fn toggle_focus_alternates() {
        let mut s = unlocked(sample_db());
        assert_eq!(s.focus, Focus::Groups);
        s.toggle_focus();
        assert_eq!(s.focus, Focus::Entries);
        s.toggle_focus();
        assert_eq!(s.focus, Focus::Groups);
    }

    #[test]
    fn search_filters_across_all_groups() {
        let mut s = unlocked(sample_db());
        s.begin_search();
        for c in "alice".chars() {
            s.type_search(c);
        }
        let refs = s.entry_refs();
        // "alice" matches Email (alice@corp), Slack (alice), and AWS (alice).
        assert_eq!(refs.len(), 3);
        let paths: Vec<Vec<String>> = refs.iter().map(|r| r.group_path.clone()).collect();
        let work = ["Work".to_string()];
        assert_eq!(
            paths.iter().filter(|p| p.as_slice() == &work[..]).count(),
            2
        );
        assert!(paths.contains(&vec!["Work".to_string(), "Projects".to_string()]));
    }

    #[test]
    fn cancel_search_clears_filter() {
        let mut s = unlocked(sample_db());
        s.begin_search();
        s.type_search('g');
        s.type_search('i');
        assert_eq!(s.entry_refs().len(), 1); // GitHub
        s.cancel_search();
        assert!(s.search_query.is_empty());
        assert!(!s.searching);
        assert_eq!(s.entry_refs().len(), 1); // back to root group's entry
    }

    #[test]
    fn lock_returns_to_unlock_and_drops_db() {
        let mut s = unlocked(sample_db());
        s.group_index = 2;
        s.lock();
        assert_eq!(s.screen, Screen::Unlock);
        assert!(s.db.is_none());
        assert_eq!(s.group_index, 0);
        assert!(s.search_query.is_empty());
    }

    #[test]
    fn unlock_sets_database_and_resets() {
        let mut s = State::default();
        s.unlock(sample_db());
        assert_eq!(s.screen, Screen::Browse);
        assert!(s.db.is_some());
        assert_eq!(s.group_index, 0);
        assert_eq!(s.entry_count(), 4);
    }

    #[test]
    fn open_and_close_detail_defaults_to_password_focus() {
        let mut s = unlocked(sample_db());
        s.group_index = 0; // Root -> GitHub
        s.open_selected();
        assert_eq!(s.screen, Screen::Detail);
        assert_eq!(s.detail_uuid, Some(uuid(0xE1)));
        let rows = s.detail_rows();
        let focused = &rows[s.detail_index];
        assert!(matches!(focused.value, DetailValue::Secret(_)));
        assert_eq!(focused.label.as_str(), "Password");
        s.close_detail();
        assert_eq!(s.screen, Screen::Browse);
    }

    #[test]
    fn copy_target_is_password_in_browse() {
        let s = unlocked(sample_db());
        let secret = s.secret_to_copy().expect("a secret to copy");
        assert_eq!(secret.expose_secret(), "pw");
    }

    #[test]
    fn add_entry_flow_transitions_title_username_password() {
        let mut s = unlocked(sample_db());
        s.begin_add_entry();
        assert_eq!(s.prompt, Prompt::AddEntryTitle);
        assert!(!s.masked_input);

        s.type_input('G');
        s.type_input('i');
        s.type_input('t');
        assert_eq!(s.commit_add_entry(), AddEntryOutcome::Continue);
        assert_eq!(
            s.prompt,
            Prompt::AddEntryUsername {
                title: "Git".to_string()
            }
        );
        assert!(!s.masked_input);

        s.type_input('o');
        s.type_input('c');
        assert_eq!(s.commit_add_entry(), AddEntryOutcome::Continue);
        assert_eq!(
            s.prompt,
            Prompt::AddEntryPassword {
                title: "Git".to_string(),
                username: "oc".to_string()
            }
        );
        assert!(s.masked_input);

        s.type_input('p');
        s.type_input('w');
        assert_eq!(
            s.commit_add_entry(),
            AddEntryOutcome::Complete {
                title: "Git".to_string(),
                username: "oc".to_string(),
                password: "pw".to_string()
            }
        );
        assert_eq!(s.prompt, Prompt::None);
        assert!(!s.masked_input);
        assert!(s.input.is_empty());
    }

    #[test]
    fn replace_db_clamps_selection_indices_to_new_bounds() {
        let mut s = unlocked(sample_db());
        // Three groups (Root, Work, Projects); Projects has one entry.
        s.group_index = 2;
        s.focus = Focus::Entries;
        s.entry_index = 5; // far beyond the one-entry list

        // Replacing with the same shape clamps entry_index to the list length.
        s.replace_db(sample_db());
        assert_eq!(s.group_index, 2);
        assert_eq!(s.entry_index, 0);

        // Shrink the database so the selected group disappears entirely.
        let mut s2 = unlocked(sample_db());
        s2.group_index = 2;
        s2.entry_index = 1;

        let mut root = group(0x1000, "Root");
        root.entries.push(entry(0xE1, "Only", "u"));
        let shrunk = Database {
            root,
            name: None,
            generator: None,
        };
        s2.replace_db(shrunk);

        assert_eq!(s2.group_nodes().len(), 1);
        assert_eq!(s2.group_index, 0);
        assert_eq!(s2.entry_index, 0);
    }

    #[test]
    fn selected_group_uuid_returns_focused_group_and_none_when_locked() {
        let mut s = unlocked(sample_db());
        s.group_index = 1; // Work
        assert_eq!(s.selected_group_uuid(), Some(uuid(0x1001)));

        s.lock();
        assert_eq!(s.selected_group_uuid(), None);
    }

    #[test]
    fn type_and_backspace_input_and_mask_flag() {
        let mut s = State::default();
        assert!(s.input.is_empty());
        assert!(!s.masked_input);

        s.type_input('a');
        s.type_input('b');
        assert_eq!(s.input, "ab");
        s.backspace_input();
        assert_eq!(s.input, "a");

        // Secret prompts set the mask flag; non-secret prompts clear it.
        s.begin_edit_field(uuid(0xE1), EntryField::Password);
        assert!(s.masked_input);
        s.begin_edit_field(uuid(0xE1), EntryField::Title);
        assert!(!s.masked_input);
        s.begin_add_group();
        assert!(!s.masked_input);
    }

    #[test]
    fn edit_field_prefills_current_value_and_masks_secrets() {
        let mut s = unlocked(sample_db());
        // Root -> GitHub (0xE1): title "GitHub", password "pw".
        s.begin_edit_field(uuid(0xE1), EntryField::Title);
        assert_eq!(s.input, "GitHub");
        assert!(!s.masked_input);

        s.begin_edit_field(uuid(0xE1), EntryField::Password);
        assert_eq!(s.input, "pw");
        assert!(s.masked_input);
    }

    #[test]
    fn detail_edit_field_maps_standard_rows_and_skips_others() {
        let mut s = unlocked(sample_db());
        s.group_index = 0; // Root -> GitHub
        s.open_selected();
        // GitHub has no URL/notes, so rows are Title(0), Username(1), Password(2).
        assert_eq!(s.detail_edit_field(), Some(EntryField::Password)); // default focus

        s.detail_index = 0;
        assert_eq!(s.detail_edit_field(), Some(EntryField::Title));
        s.detail_index = 1;
        assert_eq!(s.detail_edit_field(), Some(EntryField::UserName));
        s.detail_index = 2;
        assert_eq!(s.detail_edit_field(), Some(EntryField::Password));
        // There is no row 3 for this entry.
        s.detail_index = 3;
        assert_eq!(s.detail_edit_field(), None);
    }
}
