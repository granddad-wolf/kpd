//! Mapping from the `keepass` crate's types into `kpd-core` domain types.
//!
//! The `keepass` crate (0.17) stores the group/entry tree behind `GroupRef` and
//! `EntryRef` handles, so the conversion walks the tree through `Database`'s
//! lookup methods rather than through plain `Vec`s of children.

use chrono::TimeZone;
use keepass::db::fields::{NOTES, PASSWORD, TITLE, URL, USERNAME};
use keepass::db::{EntryRef, Group as KpGroup, Times as KpTimes};
use keepass::Database as KpDatabase;
use secrecy::SecretString;

use kpd_core::db::{Attachment, CustomField, Database, Entry, Group, Times};

/// Convert a decrypted `keepass` database into the `kpd-core` domain model.
pub(crate) fn convert(db: &KpDatabase) -> Database {
    let root = db.root();

    Database {
        root: convert_group(db, &*root),
        name: db.meta.database_name.clone(),
        generator: db.meta.generator.clone(),
    }
}

fn convert_group(db: &KpDatabase, group: &KpGroup) -> Group {
    let mut out = Group {
        uuid: group.id().uuid(),
        name: group.name.clone(),
        notes: group.notes.clone(),
        entries: Vec::new(),
        children: Vec::new(),
        times: convert_times(&group.times),
    };

    for entry_id in group.entry_ids() {
        if let Some(entry_ref) = db.entry(entry_id) {
            out.entries.push(convert_entry(&entry_ref));
        }
    }

    for group_id in group.group_ids() {
        if let Some(child) = db.group(group_id) {
            out.children.push(convert_group(db, &*child));
        }
    }

    out
}

fn convert_entry(entry_ref: &EntryRef<'_>) -> Entry {
    let entry = &**entry_ref;

    let mut out = Entry {
        uuid: entry.id().uuid(),
        title: String::new(),
        username: String::new(),
        password: SecretString::default(),
        url: None,
        notes: None,
        custom_fields: Vec::new(),
        attachments: Vec::new(),
        times: convert_times(&entry.times),
        history: Vec::new(),
    };

    // Standard KeePass fields become the named `Entry` fields; everything else
    // (TOTP seed, user-defined strings, etc.) is preserved as a custom field.
    for (name, value) in &entry.fields {
        let text = value.get().clone();
        match name.as_str() {
            TITLE => out.title = text,
            USERNAME => out.username = text,
            PASSWORD => out.password = SecretString::from(text),
            URL => out.url = Some(text),
            NOTES => out.notes = Some(text),
            _ => out.custom_fields.push(CustomField {
                key: name.clone(),
                value: SecretString::from(text),
                protected: value.is_protected(),
            }),
        }
    }

    for (name, attachment) in entry_ref.attachments_named() {
        out.attachments.push(Attachment {
            name: name.to_owned(),
            data: attachment.data.get().clone(),
        });
    }

    if let Some(history) = &entry.history {
        let len = history.get_entries().len();
        // `keepass` stores history newest-first; the `kpd-core` contract wants
        // oldest-first, so walk the history in reverse.
        for index in (0..len).rev() {
            if let Some(historical) = entry_ref.historical(index) {
                out.history.push(convert_entry(&historical));
            }
        }
    }

    out
}

fn convert_times(times: &KpTimes) -> Times {
    Times {
        creation: times.creation.map(naive_to_utc),
        last_modification: times.last_modification.map(naive_to_utc),
        last_access: times.last_access.map(naive_to_utc),
        // KeePass stores an expiry timestamp regardless of whether expiry is
        // enabled; only surface it when the entry/group actually expires.
        expiry: if times.expires == Some(true) {
            Some(naive_to_utc(times.expiry))
        } else {
            None
        },
    }
}

fn naive_to_utc(naive: chrono::NaiveDateTime) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.from_utc_datetime(&naive)
}

#[cfg(test)]
mod tests {
    use super::convert;

    use keepass::db::fields;
    use keepass::db::Value;
    use keepass::Database;
    use secrecy::ExposeSecret;

    #[test]
    fn converts_an_empty_database() {
        let db = Database::new();
        let mapped = convert(&db);

        assert!(mapped.root.children.is_empty());
        assert!(mapped.root.entries.is_empty());
        assert_eq!(mapped.name, None);
        assert_eq!(mapped.generator, None);
    }

    #[test]
    fn converts_standard_and_custom_fields() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Example");
            entry.set_unprotected(fields::USERNAME, "alice");
            entry.set_protected(fields::PASSWORD, "hunter2");
            entry.set_unprotected(fields::URL, "https://example.com");
            entry.set_unprotected(fields::NOTES, "A note");
            entry.set_unprotected("Recovery Code", "ABCD-EFGH");
            entry.set_protected("API Token", "secret-token");
        }

        let mapped = convert(&db);
        let entry = &mapped.root.entries[0];

        assert_eq!(entry.title, "Example");
        assert_eq!(entry.username, "alice");
        assert_eq!(entry.password.expose_secret(), "hunter2");
        assert_eq!(entry.url.as_deref(), Some("https://example.com"));
        assert_eq!(entry.notes.as_deref(), Some("A note"));

        assert_eq!(entry.custom_fields.len(), 2);

        let recovery = entry
            .custom_fields
            .iter()
            .find(|field| field.key == "Recovery Code")
            .expect("recovery code field should be present");
        assert!(!recovery.protected);
        assert_eq!(recovery.value.expose_secret(), "ABCD-EFGH");

        let api_token = entry
            .custom_fields
            .iter()
            .find(|field| field.key == "API Token")
            .expect("api token field should be present");
        assert!(api_token.protected);
        assert_eq!(api_token.value.expose_secret(), "secret-token");
    }

    #[test]
    fn converts_attachments() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "With attachment");
            entry.add_attachment("hello.txt", Value::unprotected(b"hello world".to_vec()));
        }

        let mapped = convert(&db);
        let entry = &mapped.root.entries[0];

        assert_eq!(entry.attachments.len(), 1);
        assert_eq!(entry.attachments[0].name, "hello.txt");
        assert_eq!(entry.attachments[0].data, b"hello world".to_vec());
    }

    #[test]
    fn converts_history_oldest_first() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "v0");
            entry.edit_tracking(|tracked| {
                tracked.set_unprotected(fields::TITLE, "v1");
            });
            entry.edit_tracking(|tracked| {
                tracked.set_unprotected(fields::TITLE, "v2");
            });
        }

        let mapped = convert(&db);
        let entry = &mapped.root.entries[0];

        assert_eq!(entry.title, "v2");
        // `keepass` records history newest-first ("v1", "v0"); the contract
        // requires oldest-first ("v0", "v1").
        assert_eq!(entry.history.len(), 2);
        assert_eq!(entry.history[0].title, "v0");
        assert_eq!(entry.history[1].title, "v1");
    }

    #[test]
    fn converts_group_hierarchy_and_uuids() {
        let mut db = Database::new();
        let entry_uuid;
        let group_uuid;
        {
            let mut root = db.root_mut();
            root.name = "Root".to_string();

            let mut child = root.add_group();
            child.name = "Child".to_string();
            group_uuid = child.id().uuid();

            let mut entry = child.add_entry();
            entry.set_unprotected(fields::TITLE, "In child");
            entry_uuid = entry.id().uuid();
        }

        let mapped = convert(&db);

        assert_eq!(mapped.root.name, "Root");
        assert_eq!(mapped.root.children.len(), 1);

        let child = &mapped.root.children[0];
        assert_eq!(child.name, "Child");
        assert_eq!(child.uuid, group_uuid);
        assert_eq!(child.entries.len(), 1);
        assert_eq!(child.entries[0].uuid, entry_uuid);
    }
}
