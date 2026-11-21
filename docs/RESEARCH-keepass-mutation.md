# keepass 0.17.0 — Mutation API research

Verified against the `keepass` **0.17.0** source (tag `v0.17.0`) and docs.rs.

Primary source files (raw, pinned to `v0.17.0`):

| File | Contents |
|---|---|
| [`src/db/types/mod.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/mod.rs) | `Database` (all methods), `GroupId`/`EntryId` ids are in group.rs/entry.rs |
| [`src/db/types/group.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/group.rs) | `Group`, `GroupRef`, `GroupMut`, `GroupTrack`, `GroupId`, `DuplicateGroupIdError`, `MoveGroupError` |
| [`src/db/types/entry.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/entry.rs) | `Entry`, `EntryRef`, `EntryMut`, `EntryTrack`, `EntryId`, `DestinationGroupNotFoundError` |
| [`src/db/types/value.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/value.rs) | `Value` |
| [`src/db/types/meta.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/meta.rs) | `Meta`, `MemoryProtection` |
| [`src/db/types/attachment.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/attachment.rs) | `Attachment`, `AttachmentRef`, `AttachmentMut`, `AttachmentId` |
| [`src/db/types/history.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/types/history.rs) | `History` |
| [`src/db/fields.rs`](https://raw.githubusercontent.com/sseemayer/keepass-rs/v0.17.0/src/db/fields.rs) | standard field-name constants |

Docs.rs reference: [`keepass::db::Database`](https://docs.rs/keepass/0.17.0/keepass/db/struct.Database.html), [`keepass::db` module](https://docs.rs/keepass/0.17.0/keepass/db/index.html).

Important architectural note (affects everything below): the database stores entries/groups/attachments in **flat `HashMap`s keyed by id**, and every `*Mut`/`*Ref` handle is a thin `{ database: &(mut) Database, id, … }` wrapper that indexes back into those maps on deref. `Database` itself is `#[derive(Clone, …)]`.

---

## 1. Mutable access to an existing nested group/entry by id

Yes. `Database` has exactly these id-based accessors (from `src/db/types/mod.rs`):

```rust
pub fn group    (&self,     id: GroupId) -> Option<GroupRef<'_>>;
pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>>;
pub fn entry    (&self,     id: EntryId) -> Option<EntryRef<'_>>;
pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>>;
```

Also on `Database`:

```rust
pub fn root(&self)       -> GroupRef<'_>;
pub fn root_mut(&mut self) -> GroupMut<'_>;
pub fn recycle_bin(&self)     -> Option<GroupRef<'_>>;   // resolves meta.recyclebin_uuid
pub fn recycle_bin_mut(&mut self) -> Option<GroupMut<'_>>;
pub fn iter_all_entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_;
pub fn foreach_entry_mut<F: FnMut(EntryMut<'_>)>(&mut self, f: F);
pub fn iter_all_groups(&self) -> impl Iterator<Item = GroupRef<'_>> + '_;
pub fn foreach_group_mut<F: FnMut(GroupMut<'_>)>(&mut self, f: F);
```

`GroupMut` additionally scopes lookups to **direct children**:

```rust
pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>>;   // only if id ∈ self.groups
pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>>;   // only if id ∈ self.entries
```

These `GroupMut`/`EntryMut` both deref to `Group`/`Entry`, so `group_mut(id).unwrap().name = …` and `.id()` work directly.

There is **no** `Database::group_mut_by_uuid`/`entry_mut_by_uuid` — you must wrap your `Uuid` in `GroupId`/`EntryId` first (see §2).

---

## 2. Id construction from a `Uuid`

Both id types are `#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]` newtypes over `Uuid`, and **both have public constructors and `From<Uuid>`**:

```rust
// GroupId (src/db/types/group.rs)
pub fn new() -> Self;                                  // random v4
pub const fn from_uuid(uuid: Uuid) -> Self;
pub fn uuid(&self) -> Uuid;
impl From<Uuid> for GroupId { fn from(uuid: Uuid) -> Self; }
impl std::fmt::Display for GroupId;                    // prints the UUID

// EntryId (src/db/types/entry.rs) — identical surface
pub fn new() -> Self;
pub const fn from_uuid(uuid: Uuid) -> Self;
pub fn uuid(&self) -> Uuid;
impl From<Uuid> for EntryId { fn from(uuid: Uuid) -> Self; }
impl std::fmt::Display for EntryId;
```

So, since `kpd` keys everything by `Uuid`:

```rust
use keepass::db::{EntryId, GroupId};

let gid: GroupId = GroupId::from_uuid(uuid);   // or: uuid.into()
let eid: EntryId = uuid.into();
db.group_mut(gid); db.entry_mut(eid);
```

You are **not** forced to round-trip through `Group::id()`/`EntryMut::id()`. `GroupMut`/`EntryMut` also expose `.id()` via `Deref` to `Group`/`Entry` (`Group::id() -> GroupId`, `Entry::id() -> EntryId`), which is the canonical way to capture the id when you *created* the object with a random id.

---

## 3. Deletion

There is **no** `Database::delete_entry`/`Database::delete_group`. Deletion lives on the `*Mut` handles (which you obtain via `entry_mut`/`group_mut`):

```rust
// hard delete a single entry
impl EntryMut<'_> { pub fn remove(mut self); }

// hard delete a group and ALL descendants (recursive)
impl GroupMut<'_> { pub fn remove(mut self); }

// tracked variants (also record the id into Database.deleted_objects)
impl EntryTrack<'_> { pub fn remove(mut self); }
impl GroupTrack<'_> { pub fn remove(self) -> Result<(), CannotDeleteRootError>; }
```

What each does:

- **`EntryMut::remove`** — removes the entry from `db.entries`, removes it from its parent group's `entries` set, removes its custom-icon back-references (including historical versions), removes attachment back-references (dropping any attachment that had this entry as its last reference), and clears any group's `last_top_visible_entry` pointing at it.
- **`GroupMut::remove`** — recursively `remove()`s every entry and child group, removes itself from its parent, then removes itself from `db.groups`. It also clears any `Meta` UUID fields that referenced this group (`recyclebin_uuid`, `entry_templates_group`, `last_selected_group`, `last_top_visible_group`).
- **`EntryTrack::remove` / `GroupTrack::remove`** — same hard delete, but first insert `id.uuid()` into `db.deleted_objects` (a public `HashMap<Uuid, Option<NaiveDateTime>>`) with `Some(Times::now())`. `GroupTrack::remove` additionally refuses to delete the **root** group (`CannotDeleteRootError`).

### Recycle bin — NOT automatic

None of the remove methods consult or move anything into `Meta.recyclebin_uuid`. They are all **hard deletes**. `recyclebin_uuid` is only *read* by `Database::recycle_bin()`/`recycle_bin_mut()`, and only *cleared* (in `GroupMut::remove`) when the recycle-bin group itself is deleted. **`kpd` must implement recycling itself**, by moving the object under the recycle-bin group before/ instead of deleting:

```rust
impl EntryMut<'_> { pub fn move_to(&mut self, group_id: GroupId) -> Result<(), DestinationGroupNotFoundError>; }
impl GroupMut<'_> { pub fn move_to(&mut self, new_parent_id: GroupId) -> Result<(), MoveGroupError>; }
impl GroupTrack<'_> { pub fn move_to(&mut self, new_parent_id: GroupId) -> Result<(), MoveGroupError>; } // also sets times.location_changed
```

A soft-delete helper would be: if `db.meta.recyclebin_uuid = Some(rb_uuid)`, then `db.entry_mut(eid)?.move_to(GroupId::from_uuid(rb_uuid))?` (entries) or `db.group_mut(gid)?.move_to(GroupId::from_uuid(rb_uuid))?` (groups).

---

## 4. Field update / removal

`Entry.fields` is a **public** field: `pub fields: HashMap<String, Value<String>>`. The setter helpers are on `Entry` (reachable through `EntryMut`/`EntryTrack` via `DerefMut`):

```rust
// src/db/types/entry.rs
pub fn set(&mut self, key: impl Into<String>, value: Value<String>);          // fields.insert(key.into(), value) — overwrites
pub fn set_unprotected(&mut self, key: impl Into<String>, value: impl Into<String>); // == set(key, Value::unprotected(value))
pub fn set_protected  (&mut self, key: impl Into<String>, value: impl Into<String>); // == set(key, Value::protected(value))
```

- **Overwrite semantics**: `set`/`set_unprotected`/`set_protected` all `HashMap::insert`, so an existing key is **replaced** (a field with the same name collapses to one value). There is no per-key "add another value with the same name".
- **Removal**: there is **no `remove_field`** method. To remove a field, mutate the public map directly: `entry_mut.fields.remove(key)`. (Setting an empty string does *not* remove the field — it stores an empty `Value`.)
- **Custom protected field**: use `set_protected("customKey", "secret")` or `set("customKey", Value::protected("secret"))`. `Value::protected(data: impl Into<T>)` wraps in `secrecy::SecretBox<T>`. (`Value` also offers `unprotected`, `is_protected()`, and `get() -> &T`.)

> **Timestamp caveat**: `Entry::set*` (and thus plain `EntryMut::set*` through deref) do **not** touch `times`. Only the `EntryTrack` wrappers (`set`, `set_unprotected`, `set_protected`) additionally set `times.last_modification = Some(Times::now())`. See §6.

---

## 5. Adding to a specific group

`GroupMut` (source `src/db/types/group.rs`):

```rust
pub fn add_group(&mut self) -> GroupMut<'_>;                                    // fresh v4 id, infallible
pub fn add_group_with_id(&mut self, id: GroupId) -> Result<GroupMut<'_>, DuplicateGroupIdError>;
pub fn add_entry(&mut self) -> EntryMut<'_>;                                    // fresh v4 id, infallible
pub fn add_entry_with_id(&mut self, id: EntryId) -> Result<EntryMut<'_>, DuplicateEntryIdError>;
```

All return the **new** `GroupMut`/`EntryMut` (so you can chain `.edit(...).id()`). `add_group`/`add_entry` internally call `add_group_with_id`/`add_entry_with_id` with a freshly generated v4 UUID and `expect` it cannot collide. To add into a specific (non-root) group:

```rust
let gid = GroupId::from_uuid(parent_uuid);
let entry = db.group_mut(gid)?.add_entry();          // returns EntryMut
// or, to pin the id:
let entry = db.group_mut(gid)?.add_entry_with_id(EntryId::from_uuid(uuid))?;
```

The new object is auto-linked into the parent's `groups`/`entries` set and into the flat `db.groups`/`db.entries` map.

---

## 6. History on edit

`set_unprotected`/`set_protected`/`set` on `Entry`/`EntryMut` do **NOT** record history — they only mutate `fields`. History is opt-in via the tracking handle:

```rust
impl EntryMut<'_> {
    pub fn track_changes(&mut self) -> EntryTrack<'_>;                        // snapshots current entry now
    pub fn edit_tracking(&mut self, f: impl FnOnce(&mut EntryTrack<'_>)) -> &mut Self; // = track_changes() + f + drop
}
impl EntryTrack<'_> {
    pub fn set(&mut self, key: impl Into<String>, value: Value<String>);      // + last_modification
    pub fn set_unprotected(&mut self, key: impl Into<String>, value: impl Into<String>); // + last_modification
    pub fn set_protected(&mut self, key: impl Into<String>, value: impl Into<String>);   // + last_modification
    pub fn add_attachment(&mut self, name: impl Into<String>, data: Value<Vec<u8>>) -> AttachmentMut<'_>;
    pub fn move_to(&mut self, group_id: GroupId) -> Result<(), DestinationGroupNotFoundError>; // + location_changed
    pub fn remove(mut self);
    pub fn edit(&mut self, f: impl FnOnce(&mut EntryTrack<'_>)) -> &mut Self;
}
```

How it works:

- `track_changes()` clones the **current** entry state into a private snapshot (`historical`), with `historical.history = None` to avoid exponential growth.
- `EntryTrack` implements `Drop`: on drop, if the entry still exists in `db.entries`, it pushes the snapshot into `entry.history` via `History::add_entry` (inserts at index 0). `History::add_entry` also `.take()`s the snapshot's own history.
- Therefore the snapshot must be taken **before** the edits. Intended pattern:

```rust
db.entry_mut(eid)?.edit_tracking(|e| {
    e.set_unprotected(fields::TITLE, "New title");
    e.set_protected(fields::PASSWORD, "new password");
});
// on drop, the pre-edit entry is appended to history[0]
```

If you call `track_changes()` *after* already mutating via `EntryMut`, the snapshot will include your edits (so no meaningful history is recorded).

Notes:
- `edit_tracking` itself does **not** set `times.last_modification`; that is done by each `EntryTrack::set_*`/`edit`/`add_attachment` method. Direct field mutation through `DerefMut` inside the closure (e.g. `e.tags.push(...)`, `e.fields.remove(...)`) will **not** bump `last_modification` — set `e.times.last_modification = Some(Times::now())` yourself if that matters.
- `EntryTrack::remove` records the id in `db.deleted_objects` before performing the hard delete.

---

## 7. Attachments

```rust
impl EntryMut<'_> {
    pub fn add_attachment(&mut self, name: impl Into<String>, data: Value<Vec<u8>>) -> AttachmentMut<'_>;
    pub fn remove_attachment_by_name(&mut self, name: &str);
    pub fn remove_attachment_by_id(&mut self, attachment_id: AttachmentId);
    pub fn attachment_mut(&mut self, id: AttachmentId) -> Option<AttachmentMut<'_>>;
    pub fn attachment_by_name_mut(&mut self, name: &str) -> Option<AttachmentMut<'_>>;
    pub fn foreach_attachment_mut<F: FnMut(AttachmentMut<'_>)>(&mut self, f: F);
}

impl AttachmentMut<'_> {
    pub fn remove(mut self);   // removes attachment from db AND all references to it
    pub fn edit(&mut self, f: impl FnOnce(&mut AttachmentMut<'_>)) -> &mut Self;
}
// Attachment itself derefs to Value<Vec<u8>>, so `attachment.data = Value::unprotected(bytes)` works.

impl Database {
    pub fn remove_unused_attachments(&mut self) -> usize;
}
```

- `add_attachment` allocates the next free `AttachmentId` (`AttachmentId::next_free`, a plain `usize`), stores the bytes in `db.attachments`, and records `(entry_id, None)` in the attachment's back-reference set. If an attachment with the same **name** already exists on this entry, the old one is removed (`remove_attachment_by_id`).
- `remove_attachment_by_name`/`remove_attachment_by_id` remove the reference from the entry, and if the attachment has no remaining referers, remove it from `db.attachments` entirely.
- `Database::remove_unused_attachments()` rebuilds each attachment's referer set from all entries **and their history**, then drops any attachment nothing refers to; returns the count removed. Use it after trimming/replacing `entry.history` directly.

---

## 8. Meta mutation

`Database.meta` is a **public field**, and so is `Database.config` and `Database.deleted_objects`:

```rust
pub struct Database {
    pub config: DatabaseConfig,
    pub meta: Meta,
    pub deleted_objects: HashMap<Uuid, Option<NaiveDateTime>>,
    /* private fields */
}
```

`Meta` (source `src/db/types/meta.rs`) has **all public fields**; no accessor methods. The fields relevant to `kpd`:

```rust
pub struct Meta {
    pub generator: Option<String>,
    pub database_name: Option<String>,
    pub database_description: Option<String>,
    pub default_username: Option<String>,
    pub recyclebin_enabled: Option<bool>,
    pub recyclebin_uuid: Option<Uuid>,          // note: Option<Uuid>, NOT Option<GroupId>
    pub entry_templates_group: Option<Uuid>,
    pub memory_protection: Option<MemoryProtection>,
    pub history_max_items: Option<isize>,
    pub history_max_size: Option<isize>,
    pub custom_data: HashMap<String, CustomDataItem>,
    // … plus *_changed / last_selected_group / last_top_visible_group / color etc.
}
```

`MemoryProtection` has public bool fields `protect_title`, `protect_username`, `protect_password`, `protect_url`, `protect_notes`; `Default` sets only `protect_password = true`.

So mutate directly:

```rust
db.meta.generator = Some("kpd".into());
db.meta.database_name = Some("My vault".into());
db.meta.recyclebin_uuid = Some(group_id.uuid());          // GroupId -> .uuid()
db.meta.recyclebin_enabled = Some(true);
db.meta.memory_protection = Some(keepass::db::MemoryProtection {
    protect_title: true, protect_username: true, ..Default::default()
});
```

No method, no builder. `db.meta` can be reached even while holding a `*Mut` handle via `Database::meta` — but note the borrow rules in §9.

---

## 9. Gotchas (borrow-checker / aliasing / id stability)

1. **All `*Mut` handles hold `&mut Database`.** `GroupMut`, `EntryMut`, `AttachmentMut`, `EntryTrack`, `GroupTrack` each own an exclusive borrow of the whole database. You cannot hold two of them at once, and you cannot call `db.group_mut()`/`db.entry_mut()`/`db.root_mut()` while any other mutable handle is live.

2. **`*Ref` handles hold `&Database` and will block mutation.** `GroupRef`/`EntryRef`/`AttachmentRef` borrow the database immutably for their whole lifetime. So holding a `GroupRef` (e.g. from `db.root()` or an iterator) while calling `db.group_mut(...)` is a borrow error. Concrete failure: iterating `db.iter_all_entries()` and calling `db.entry_mut(e.id())` inside the loop won't compile. **Workaround**: collect the (Copy) ids first, then mutate — exactly what the crate's own `foreach_entry_mut`/`foreach_group_mut` do internally:
   ```rust
   let ids: Vec<EntryId> = db.iter_all_entries().map(|e| e.id()).collect();
   for id in ids { if let Some(mut e) = db.entry_mut(id) { /* … */ } }
   ```

3. **`remove(self)` consumes the handle** (takes `self` by value). The underlying object is gone afterward; re-fetch if needed. `GroupMut::remove`/`EntryMut::remove` don't return anything.

4. **Root group is not guarded by `GroupMut::remove`.** Plain `GroupMut::remove` has no root check and would recursively delete everything including the root, leaving an empty `db.groups` map. Use `GroupTrack::remove` (returns `Err(CannotDeleteRootError)` for the root) or check `gid != db.root().id()` yourself.

5. **Ids are stable.** `GroupId`/`EntryId` are `Copy` newtypes over `Uuid`; nothing renumbers them on edit. `move_to` changes `parent` (and `previous_parent_group`) but keeps the id. Historical versions share the entry's `EntryId` and are addressed by a `history_index` inside the handle. After a mutation you do **not** need to re-fetch for the id to stay valid — but after a `remove`, the id dangles.

6. **`track_changes()` must be called before edits** to snapshot the correct pre-edit state (see §6). Also, only `EntryTrack::set_*`/`edit` bump `times.last_modification`; plain `EntryMut::set_*` and direct field writes do **not**.

7. **Recycle bin is not automatic** (§3). If `kpd` wants KeePass-style recycling, it must `move_to` the recycle-bin group itself and set `meta.recyclebin_uuid`.

8. **`Entry.fields` / `Entry.history` / `Entry.tags` etc. are public**, so you can bypass the helpers; just remember the helpers are what track history/times when you go through `EntryTrack`.

---

## Recommended `DbHandle` mutation API (operating by `Uuid`)

Assume `db: Database`, and `DbHandle` wraps `db`. `GroupId::from_uuid(u)` / `EntryId::from_uuid(u)` are the id conversions; `keepass::db::fields::{TITLE, USERNAME, PASSWORD, URL, NOTES}` are the standard keys.

### add_entry(parent_uuid, title, username, password)
```rust
let gid = GroupId::from_uuid(parent_uuid);
let entry = db.group_mut(gid)?.add_entry();            // EntryMut<'_>
entry.set_unprotected(fields::TITLE, title);
entry.set_unprotected(fields::USERNAME, username);
entry.set_protected(fields::PASSWORD, password);
let new_uuid = entry.id().uuid();                      // capture before drop
// (or pin the id: db.group_mut(gid)?.add_entry_with_id(EntryId::from_uuid(uuid))?)
```

### update_entry_field(entry_uuid, key, value, protected)
```rust
let eid = EntryId::from_uuid(entry_uuid);
if let Some(mut e) = db.entry_mut(eid) {
    e.edit_tracking(|t| {                               // history snapshot + last_modification
        if protected { t.set_protected(key, value); } else { t.set_unprotected(key, value); }
    });
}
// remove a field:
//   if let Some(mut e) = db.entry_mut(eid) {
//       e.edit_tracking(|t| { t.fields.remove(key); t.times.last_modification = Some(Times::now()); });
//   }
```

### delete_entry(entry_uuid, soft: bool)
```rust
let eid = EntryId::from_uuid(entry_uuid);
if soft {
    if let Some(rb) = db.meta.recyclebin_uuid {                       // move to recycle bin
        db.entry_mut(eid)?.move_to(GroupId::from_uuid(rb))?;
    }
} else if let Some(e) = db.entry_mut(eid) {
    e.track_changes().remove();                                       // records deleted_objects + hard delete
}
```

### add_group(parent_uuid, name)
```rust
let gid = GroupId::from_uuid(parent_uuid);
let group = db.group_mut(gid)?.add_group();           // GroupMut<'_>
group.name = name.to_string();
let new_uuid = group.id().uuid();
// (or pin: db.group_mut(gid)?.add_group_with_id(GroupId::from_uuid(uuid))?)
```

### delete_group(group_uuid, soft: bool)
```rust
let gid = GroupId::from_uuid(group_uuid);
if soft {
    if let Some(rb) = db.meta.recyclebin_uuid {
        db.group_mut(gid)?.move_to(GroupId::from_uuid(rb))?;          // Err(MoveGroupError::CannotMoveRoot) for root
    }
} else if gid != db.root().id() {
    db.group_mut(gid)?.track_changes().remove()?;                     // guards root, records deleted_objects
}
```

All `*_uuid` arguments are raw `uuid::Uuid` values from the app's own keying; convert once with `GroupId::from_uuid`/`EntryId::from_uuid` (or `.into()`).
