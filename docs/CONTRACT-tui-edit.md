# Contract: kpd-tui edit/save (Phase 3b-2)

Extends the read-only TUI with create/edit/delete/save. Refer to
`agent/SPEC-read-only-mvp.md` (existing screens), `agent/adr/0005-write-path.md`
(save), and `agent/adr/0006-mutation-api.md` (mutation methods).

## App ownership change (in `kpd/crates/kpd-tui/src/app.rs`)

`App` must own the write-path handle and the session key:

```rust
pub struct App {
    pub config: AppConfig,
    pub state: State,
    handle: Option<kpd_kdbx::DbHandle>,   // NEW
    key: Option<kpd_crypto::CompositeKey>, // NEW: session key for save (zeroized on lock/quit)
    // ...existing unlock input, unlock_error, status, clipboard_guard...
}
```

- `try_unlock`: build the `CompositeKey`, call `kpd_kdbx::DbHandle::open(&path, &key)`;
  on success store `self.key = Some(key)` and `self.handle = Some(handle)`, then
  `self.state.unlock(handle.view())`. On failure, `key` drops (zeroized).
- `lock`: take and drop `handle` + `key`, clear clipboard guard, return to unlock.

## State additions (in `kpd/crates/kpd-tui/src/state.rs`)

`State` gains a prompt model and a refresh method (keep it pure — `kpd_kdbx::EntryField`
is a pure enum, so it may be used here):

```rust
#[derive(Debug, Clone)]
pub enum Prompt {
    None,
    AddEntryTitle,
    AddEntryUsername { title: String },
    AddEntryPassword { title: String, username: String },
    AddGroupName,
    EditField { entry_uuid: Uuid, field: kpd_kdbx::EntryField },
    ConfirmDeleteEntry { entry_uuid: Uuid },
    ConfirmDeleteGroup { group_uuid: Uuid },
    ConfirmSave,
}

// State gains:
pub prompt: Prompt,        // default Prompt::None
pub input: String,         // current prompt text buffer
pub masked_input: bool,    // true while entering a secret

impl State {
    /// Replace the database view after a mutation WITHOUT resetting selection;
    /// clamp group_index / entry_index / detail_index to new bounds.
    pub fn replace_db(&mut self, db: Database);
    pub fn type_input(&mut self, c: char);
    pub fn backspace_input(&mut self);
    /// The currently selected group's UUID (for add entry/group targets).
    pub fn selected_group_uuid(&self) -> Option<Uuid>;
}
```

`masked_input` is `true` for `AddEntryPassword` and `EditField` (password/secret);
`false` otherwise. The renderer shows `*` when `masked_input`.

## Keybindings (added to the existing handlers)

- Browse: `a` → begin `AddEntryTitle` (current group); `g` → `AddGroupName`;
  `e` → `EditField { entry: selected, field: Password }`;
  `d` → `ConfirmDeleteEntry { selected }`; `x` → `ConfirmDeleteGroup { current group }`.
- Detail: `e` → `EditField { entry, field: focused field }` (map `detail_index` to
  `Title`/`UserName`/`Password`/`Url`/`Notes`; skip non-editable rows);
  `d` → `ConfirmDeleteEntry`.
- Any unlocked screen: `Ctrl+S` → `ConfirmSave`.
- While a prompt is active (any `Prompt != None`): printable chars go to `input`
  (respecting `masked_input`), `Backspace` deletes, `Enter` commits, `Esc` cancels
  (clear prompt + input, back to the prior screen). `ConfirmDelete*`/`ConfirmSave`
  accept `y`/`Y` as "yes" and anything else as "cancel".

## App prompt commit logic (in `app.rs`)

On `Enter` with an active prompt, `App` executes the mutation via `self.handle`
(after which it refreshes the view with `state.replace_db(handle.view())`):

- `AddEntryTitle` → store title, advance to `AddEntryUsername`.
- `AddEntryUsername` → store username, advance to `AddEntryPassword`.
- `AddEntryPassword` → `handle.add_entry(group_uuid, &title, &username, &password)`,
  refresh, clear prompt, status "entry added".
- `AddGroupName` → `handle.add_group(group_uuid, &name)`, refresh, clear prompt.
- `EditField` → `handle.set_entry_field(entry_uuid, field, &input)`, refresh, clear.
- `ConfirmDeleteEntry` (`y`) → `handle.delete_entry(entry_uuid)`, refresh, clear.
- `ConfirmDeleteGroup` (`y`) → `handle.delete_group(group_uuid)`, refresh, clear.
- `ConfirmSave` (`y`) → `self.save()` (below), clear prompt.

All mutation errors are surfaced in the status bar (never panic). The clipboard
guard is dropped on any mutation that changes the copied entry if convenient, but
at minimum on `lock` (already done).

## Save flow

```rust
fn save(&mut self) {
    // requires self.handle and self.key
    match self.handle.as_ref().unwrap().save(self.key.as_ref().unwrap(), &SaveOptions::default()) {
        Ok(report) => status = Info(format!(
            "saved {} bytes{}{}", report.bytes_written,
            if report.backup_path.is_some() { " (backup written)" } else { "" },
            if report.warnings.is_empty() { "" } else { " — warnings present" }),
        Err(err) => status = Info(format!("save failed: {err}")),
    }
}
```

The `ConfirmSave` prompt must show the lossy-field warning text before the user
confirms (render the warning from a constant in `ui.rs`, or read it back from a
failed/`report.warnings` — simplest: show a static warning line in the confirm UI).

## UI rendering (in `ui.rs`)

- Render the active `Prompt` as a one-line input bar at the bottom of the current
  screen (label + `input` masked per `masked_input` + a hint), with the warning
  line for `ConfirmSave`.

## Tests (pure, TTY-free, in `state.rs`)

- prompt transitions for the add-entry flow (title → username → password).
- `replace_db` keeps selection in bounds after the selected entry/group is removed.
- `selected_group_uuid` returns the focused group and `None` when locked.
- `type_input`/`backspace_input`/`masked_input` behavior.

## Constraints

Edition 2021, no `unsafe`. Do NOT modify other crates, the workspace
`kpd/Cargo.toml`, the binary, or `agent/` files. Verify `kpd_kdbx::DbHandle` /
`EntryField` / `SaveOptions` / `SaveReport` signatures by reading
`kpd/crates/kpd-kdbx/src/lib.rs` (they are implemented) and code against them
exactly. There is no Rust compiler here — write compiling-ready code.
