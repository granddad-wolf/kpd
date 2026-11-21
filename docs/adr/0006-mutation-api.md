# ADR-0006: Mutation API — DbHandle add/edit/delete by UUID

- **Status**: accepted (design). Implementation is Phase 3b-1 (backend) then 3b-2 (TUI).
- **Date**: 2026-11-17
- **Input**: `agent/RESEARCH-keepass-mutation.md` (verified against `keepass` 0.17.0).

## Context

`keepass` 0.17.0 exposes mutation via `Database::group_mut(GroupId)` /
`entry_mut(EntryId)`, `GroupMut::add_group`/`add_entry`, `Entry::set_unprotected`/
`set_protected`, `EntryMut::edit_tracking` (history), and `EntryMut::remove`/
`GroupMut::remove`. Ids are `Copy` newtypes over `Uuid` constructible via
`GroupId::from_uuid`/`EntryId::from_uuid`. Deletion is hard; recycle bin is not
automatic (use `move_to`). All `*Mut` handles hold `&mut Database`, so we must
not hold two at once nor hold a `*Ref` while mutating.

## Decisions

1. **`DbHandle` owns mutation.** Add `&mut self` methods on `DbHandle` that take
   raw `uuid::Uuid` values and convert internally. `kpd-core` stays a read-only
   projection; the TUI keeps calling `view()` after each mutation to refresh it.
2. **History + timestamps via `edit_tracking`.** Field edits go through
   `EntryMut::edit_tracking` so the pre-edit state is recorded in history and
   `last_modification` is bumped. Deletes go through `track_changes().remove()`
   to write a `deleted_objects` tombstone (KeePass-compatible).
3. **Field protection:** `Password` and `Custom(..)` are stored `set_protected`;
   `Title`/`UserName`/`Url`/`Notes` are `set_unprotected`.
4. **Deletion is hard for the MVP.** `delete_entry`/`delete_group` hard-delete
   (with a tombstone). Soft-delete/recycle-bin (`move_to`) is a follow-up; the
   root group is refused with a dedicated error.

## Phase 3b-1 public API (implementation contract for `kpd-kdbx`)

Add to `kpd/crates/kpd-kdbx/src/lib.rs`; add `uuid = "1"` to that crate's
`Cargo.toml` (it unifies with `kpd-core`'s `uuid`).

```rust
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryField {
    Title,
    UserName,
    Password,
    Url,
    Notes,
    /// A custom string field, stored protected by default.
    Custom(String),
}

#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    // ...existing NotFound, Io, WrongCredentials, Parse, UnsupportedForWrite...
    #[error("the root group cannot be deleted")]
    CannotDeleteRoot,
}

impl DbHandle {
    // existing: open, view, save

    /// Add an entry under `parent_uuid`; returns the new entry's UUID.
    pub fn add_entry(
        &mut self,
        parent_uuid: Uuid,
        title: &str,
        username: &str,
        password: &str,
    ) -> Result<Uuid, KdbxError>;

    /// Set one field of an entry (recorded in history).
    pub fn set_entry_field(
        &mut self,
        entry_uuid: Uuid,
        field: EntryField,
        value: &str,
    ) -> Result<(), KdbxError>;

    /// Hard-delete an entry (records a `deleted_objects` tombstone).
    pub fn delete_entry(&mut self, entry_uuid: Uuid) -> Result<(), KdbxError>;

    /// Add a child group under `parent_uuid`; returns the new group's UUID.
    pub fn add_group(&mut self, parent_uuid: Uuid, name: &str) -> Result<Uuid, KdbxError>;

    /// Hard-delete a group and its descendants (root refused).
    pub fn delete_group(&mut self, group_uuid: Uuid) -> Result<(), KdbxError>;
}
```

Implementation notes (from the research):

- `add_entry`: `self.inner.group_mut(GroupId::from_uuid(parent_uuid))` (map
  `None` → `NotFound`) then `.add_entry()`, then
  `set_unprotected(fields::TITLE/TITLE …)` / `set_protected(fields::PASSWORD, …)`;
  capture `entry.id().uuid()` before the handle drops.
- `set_entry_field`: `self.inner.entry_mut(EntryId::from_uuid(entry_uuid))` then
  `.edit_tracking(|t| { t.set_unprotected(key, value) | t.set_protected(key, value) })`.
  Map the `EntryField` to the KeePass key via `keepass::db::fields::{TITLE,
  USERNAME, PASSWORD, URL, NOTES}`.
- `delete_entry`: `self.inner.entry_mut(eid)` then `.track_changes().remove()`.
- `add_group`: `group_mut(gid)?.add_group()`, set `.name`, capture `.id().uuid()`.
- `delete_group`: guard `gid == self.inner.root().id()` → `CannotDeleteRoot`;
  else `group_mut(gid)?.track_changes().remove()` (map its error → `KdbxError`).
- Missing id everywhere → `KdbxError::NotFound(...)`.

## Tests (in `lib.rs` `#[cfg(test)]`)

Seed a temp `.kdbx` (existing pattern: build `KpDatabase::new()` + builders,
`save` to a file, `DbHandle::open`), then assert: add_entry returns a UUID and
`view()` shows the entry (password protected); set_entry_field updates title and
adds a history entry; delete_entry removes it; add_group nests under a parent;
delete_group removes the subtree; deleting the root returns `CannotDeleteRoot`.
Clean up temp files (reuse a `TempFiles` guard).

## Consequences

- 3b-2: TUI edit/add/delete/save screens; `App` owns the `DbHandle` and refreshes
  the `State` view after each mutation; save shows the ADR-0005 lossy-field
  warning and requires confirmation.
- Soft-delete/recycle-bin and custom-field editing are follow-ups (the API is
  shaped to allow them: `move_to`, `EntryField::Custom`).
