//! Domain model for kpd: databases, groups, entries, attachments, and history.

pub mod db;

pub use db::{Attachment, CustomField, Database, Entry, EntryRef, Group, Times};
