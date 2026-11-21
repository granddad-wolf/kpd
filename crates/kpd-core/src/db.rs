use chrono::{DateTime, Utc};
use secrecy::SecretString;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct Database {
    pub root: Group,
    /// KDBX `DatabaseName`, if set.
    pub name: Option<String>,
    /// KDBX `Generator` field, if set.
    pub generator: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    pub uuid: Uuid,
    pub name: String,
    pub notes: Option<String>,
    pub entries: Vec<Entry>,
    pub children: Vec<Group>,
    pub times: Times,
}

#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub uuid: Uuid,
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Custom string fields other than the standard ones above.
    pub custom_fields: Vec<CustomField>,
    pub attachments: Vec<Attachment>,
    pub times: Times,
    /// Previous versions (KDBX4 entry history), oldest first.
    pub history: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub struct CustomField {
    pub key: String,
    pub value: SecretString,
    pub protected: bool,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Times {
    pub creation: Option<DateTime<Utc>>,
    pub last_modification: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
    pub expiry: Option<DateTime<Utc>>,
}

/// Locator for an entry plus the group path leading to it (root-first).
#[derive(Debug, Clone)]
pub struct EntryRef {
    pub group_path: Vec<String>,
    pub entry_uuid: Uuid,
}

impl Database {
    /// Case-insensitive substring match across title, username, url, and notes.
    /// Empty query returns `all_entries()`.
    pub fn search(&self, query: &str) -> Vec<EntryRef> {
        if query.is_empty() {
            return self.all_entries();
        }

        let needle = query.to_lowercase();
        let mut out = Vec::new();
        let mut path = Vec::new();
        walk_group(&self.root, &mut path, &mut |entry, group_path| {
            let matches = entry.title.to_lowercase().contains(needle.as_str())
                || entry.username.to_lowercase().contains(needle.as_str())
                || entry
                    .url
                    .as_deref()
                    .is_some_and(|url| url.to_lowercase().contains(needle.as_str()))
                || entry
                    .notes
                    .as_deref()
                    .is_some_and(|notes| notes.to_lowercase().contains(needle.as_str()));
            if matches {
                out.push(EntryRef {
                    group_path: group_path.to_vec(),
                    entry_uuid: entry.uuid,
                });
            }
        });
        out
    }

    /// Every entry with its group path (root-first, root name excluded).
    pub fn all_entries(&self) -> Vec<EntryRef> {
        let mut out = Vec::new();
        let mut path = Vec::new();
        walk_group(&self.root, &mut path, &mut |entry, group_path| {
            out.push(EntryRef {
                group_path: group_path.to_vec(),
                entry_uuid: entry.uuid,
            });
        });
        out
    }

    pub fn entry(&self, uuid: Uuid) -> Option<&Entry> {
        find_entry(&self.root, uuid)
    }

    pub fn group_by_uuid(&self, uuid: Uuid) -> Option<&Group> {
        find_group(&self.root, uuid)
    }
}

/// Depth-first, pre-order traversal. `path` holds the group names from the root
/// down to (but not including) the group currently being visited; the root's
/// own name is never pushed, so entries directly under the root get an empty
/// path.
fn walk_group(group: &Group, path: &mut Vec<String>, visit: &mut impl FnMut(&Entry, &[String])) {
    for entry in &group.entries {
        visit(entry, path);
    }
    for child in &group.children {
        path.push(child.name.clone());
        walk_group(child, path, visit);
        path.pop();
    }
}

fn find_entry(group: &Group, uuid: Uuid) -> Option<&Entry> {
    for entry in &group.entries {
        if entry.uuid == uuid {
            return Some(entry);
        }
    }
    for child in &group.children {
        if let Some(found) = find_entry(child, uuid) {
            return Some(found);
        }
    }
    None
}

fn find_group(group: &Group, uuid: Uuid) -> Option<&Group> {
    if group.uuid == uuid {
        return Some(group);
    }
    for child in &group.children {
        if let Some(found) = find_group(child, uuid) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use uuid::Uuid;

    fn e1() -> Uuid {
        Uuid::from_u128(0xE1)
    }
    fn e2() -> Uuid {
        Uuid::from_u128(0xE2)
    }
    fn e3() -> Uuid {
        Uuid::from_u128(0xE3)
    }
    fn e4() -> Uuid {
        Uuid::from_u128(0xE4)
    }
    fn g_root() -> Uuid {
        Uuid::from_u128(0x1000)
    }
    fn g_work() -> Uuid {
        Uuid::from_u128(0x1001)
    }
    fn g_projects() -> Uuid {
        Uuid::from_u128(0x1002)
    }
    fn g_personal() -> Uuid {
        Uuid::from_u128(0x1003)
    }

    fn group(uuid: Uuid, name: &str) -> Group {
        Group {
            uuid,
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn entry_uuids(refs: Vec<EntryRef>) -> Vec<Uuid> {
        refs.into_iter().map(|r| r.entry_uuid).collect()
    }

    fn sample_db() -> Database {
        let mut root = group(g_root(), "Root");

        root.entries.push(Entry {
            uuid: e1(),
            title: "GitHub Login".to_string(),
            username: "octocat".to_string(),
            password: SecretString::from("correct horse battery staple"),
            url: Some("https://github.com".to_string()),
            notes: Some("Work account, 2FA enabled".to_string()),
            ..Default::default()
        });

        let mut work = group(g_work(), "Work");
        work.entries.push(Entry {
            uuid: e2(),
            title: "Email".to_string(),
            username: "alice@corp.example".to_string(),
            password: SecretString::from("s3cret"),
            ..Default::default()
        });

        let mut projects = group(g_projects(), "Projects");
        projects.entries.push(Entry {
            uuid: e3(),
            title: "AWS Console".to_string(),
            username: "alice".to_string(),
            password: SecretString::from("p@ss"),
            ..Default::default()
        });
        work.children.push(projects);

        let mut personal = group(g_personal(), "Personal");
        personal.entries.push(Entry {
            uuid: e4(),
            title: "Bank".to_string(),
            username: "alice".to_string(),
            password: SecretString::from("1234"),
            ..Default::default()
        });

        root.children.push(work);
        root.children.push(personal);

        Database {
            root,
            name: Some("Sample".to_string()),
            generator: Some("kpd-core-test".to_string()),
        }
    }

    #[test]
    fn search_is_case_insensitive_across_fields() {
        let db = sample_db();

        // Title match with mixed case.
        assert_eq!(entry_uuids(db.search("gITHub")), vec![e1()]);
        // Username match.
        assert_eq!(entry_uuids(db.search("octocat")), vec![e1()]);
        // URL match.
        assert_eq!(entry_uuids(db.search("https://github.com")), vec![e1()]);
        // Notes match with mixed case.
        assert_eq!(entry_uuids(db.search("WORK ACCOUNT")), vec![e1()]);
        // Username substring shared across several entries.
        assert_eq!(entry_uuids(db.search("alice")), vec![e2(), e3(), e4()]);
        // No match.
        assert!(db.search("does-not-exist").is_empty());
    }

    #[test]
    fn search_empty_query_returns_all_entries() {
        let db = sample_db();
        assert_eq!(entry_uuids(db.search("")), entry_uuids(db.all_entries()));
    }

    #[test]
    fn all_entries_walks_root_first_and_excludes_root_name() {
        let db = sample_db();
        let refs = db.all_entries();

        let paths: Vec<Vec<String>> = refs.iter().map(|r| r.group_path.clone()).collect();
        assert_eq!(
            paths,
            vec![
                Vec::<String>::new(),
                vec!["Work".to_string()],
                vec!["Work".to_string(), "Projects".to_string()],
                vec!["Personal".to_string()],
            ]
        );

        // Depth-first, pre-order: root entries first, then each subtree in order.
        assert_eq!(entry_uuids(refs), vec![e1(), e2(), e3(), e4()]);
    }

    #[test]
    fn group_by_uuid_finds_groups() {
        let db = sample_db();
        assert_eq!(db.group_by_uuid(g_root()).map(|g| g.name.as_str()), Some("Root"));
        assert_eq!(db.group_by_uuid(g_work()).map(|g| g.name.as_str()), Some("Work"));
        assert_eq!(
            db.group_by_uuid(g_projects()).map(|g| g.name.as_str()),
            Some("Projects")
        );
        assert_eq!(
            db.group_by_uuid(g_personal()).map(|g| g.name.as_str()),
            Some("Personal")
        );
        assert!(db.group_by_uuid(Uuid::from_u128(0xDEAD)).is_none());
    }

    #[test]
    fn entry_finds_entries_by_uuid() {
        let db = sample_db();
        assert_eq!(db.entry(e2()).map(|e| e.title.as_str()), Some("Email"));
        assert_eq!(db.entry(e4()).map(|e| e.username.as_str()), Some("alice"));
        assert!(db.entry(Uuid::from_u128(0xDEAD)).is_none());
    }
}
