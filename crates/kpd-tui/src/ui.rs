//! ratatui rendering for each screen.
//!
//! Secret values are only ever exposed here (via [`ExposeSecret`]) to display
//! them after the user toggles reveal, or handed off untouched to the clipboard
//! call. They are never written to disk or logs.

use kpd_core::db::{Database, EntryRef};
use kpd_kdbx::EntryField;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use secrecy::ExposeSecret;

use crate::app::{App, Status};
use crate::state::{DetailValue, Focus, Prompt, Screen};

/// Standing save caveat shown before a save is confirmed: re-serializing the
/// database from the in-memory model drops un-modeled / vendor-extension XML
/// fields (e.g. KeePassXC `<PreviousParentGroup>`).
const LOSSY_SAVE_WARNING: &str = "warning: saving re-serializes the database; \
un-modeled or vendor-extension XML fields (e.g. KeePassXC <PreviousParentGroup>) \
may be dropped";

/// Render the current screen, with a persistent key-hint bar on the last row.
pub fn render(frame: &mut Frame, app: &App) {
    let [body, tips] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(frame.area());
    match app.state.screen {
        Screen::Unlock => render_unlock(frame, app, body),
        Screen::Browse => render_browse(frame, app, body),
        Screen::Detail => render_detail(frame, app, body),
    }
    if app.state.plugin_menu.is_some() {
        render_plugin_menu(frame, app);
    }
    if let Some(result) = &app.state.plugin_result {
        render_plugin_result(frame, result);
    }
    if let Some(label) = app.conflict_label() {
        render_conflict(frame, label);
    }
    render_key_bar(frame, app, tips);
}

fn render_unlock(frame: &mut Frame, app: &App, area: Rect) {
    let area = centered(area, 80, 16);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "kpd — unlock database",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "Database: {}",
        app.config.location.label()
    )));
    match &app.config.key_file {
        Some(key_file) => lines.push(Line::from(format!("Key file: {}", key_file.display()))),
        None => lines.push(Line::from("Key file: (none)")),
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("Master password: "),
        Span::styled(
            "*".repeat(app.unlock_password_len()),
            Style::default().fg(Color::Yellow),
        ),
    ]));
    if let Some(err) = app.unlock_error() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err,
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::from(""));
    if let Some(busy) = app.busy_label() {
        lines.push(Line::from(Span::styled(
            busy,
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(Span::styled(
        "Enter = unlock · Esc = quit",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines)
        .block(Block::bordered().title("Unlock"))
        // Long cloud errors (timeouts, URLs) wrap instead of being clipped.
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_browse(frame: &mut Frame, app: &App, area: Rect) {
    let prompt_h = prompt_lines(app);
    let [main, prompt_area, status] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(prompt_h),
        Constraint::Length(1),
    ])
    .areas(area);
    let [groups, entries] =
        Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)]).areas(main);

    render_groups(frame, app, groups);
    render_entries(frame, app, entries);
    render_prompt(frame, app, prompt_area);
    render_status(frame, app, status);
}

fn render_groups(frame: &mut Frame, app: &App, area: Rect) {
    let nodes = app.state.group_nodes();
    let items: Vec<ListItem> = nodes
        .iter()
        .map(|node| {
            let indent = "  ".repeat(node.depth);
            ListItem::new(format!("{indent}{}", node.name))
        })
        .collect();

    let title = if app.state.focus == Focus::Groups {
        "Groups ◄"
    } else {
        "Groups"
    };
    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut state = ListState::default();
    state.select(Some(app.state.group_index));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_entries(frame: &mut Frame, app: &App, area: Rect) {
    let refs = app.state.entry_refs();
    let items: Vec<ListItem> = match app.state.db.as_ref() {
        Some(db) => refs.iter().map(|r| entry_item(db, r)).collect(),
        None => Vec::new(),
    };

    let mut title = if app.state.searching {
        format!("Entries — search: {}", app.state.search_query)
    } else if !app.state.search_query.is_empty() {
        format!("Entries — filter: {}", app.state.search_query)
    } else {
        "Entries".to_string()
    };
    if app.state.focus == Focus::Entries {
        title.push_str(" ◄");
    }

    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut state = ListState::default();
    state.select(Some(app.state.entry_index));
    frame.render_stateful_widget(list, area, &mut state);
}

fn entry_item(db: &Database, entry_ref: &EntryRef) -> ListItem<'static> {
    match db.entry(entry_ref.entry_uuid) {
        Some(entry) => {
            let title = if entry.title.is_empty() {
                "(untitled)"
            } else {
                entry.title.as_str()
            };
            let mut text = format!("{title} — {}", entry.username);
            if !entry_ref.group_path.is_empty() {
                text.push_str(&format!("   [{}]", entry_ref.group_path.join("/")));
            }
            ListItem::new(text)
        }
        None => ListItem::new(String::new()),
    }
}

fn render_detail(frame: &mut Frame, app: &App, area: Rect) {
    let prompt_h = prompt_lines(app);
    let [main, prompt_area, status] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(prompt_h),
        Constraint::Length(1),
    ])
    .areas(area);

    let rows = app.state.detail_rows();
    let items: Vec<ListItem> = rows.iter().map(|row| detail_item(app, row)).collect();

    let list = List::new(items)
        .block(Block::bordered().title("Entry detail"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut state = ListState::default();
    state.select(Some(app.state.detail_index));
    frame.render_stateful_widget(list, main, &mut state);

    render_prompt(frame, app, prompt_area);
    render_status(frame, app, status);
}

fn detail_item(app: &App, row: &crate::state::DetailRow) -> ListItem<'static> {
    let value = match &row.value {
        DetailValue::Text(text) => text.clone(),
        DetailValue::Secret(secret) => {
            if app.state.reveal_secrets {
                secret.expose_secret().to_string()
            } else {
                "••••••••".to_string()
            }
        }
    };
    ListItem::new(format!("{}: {}", row.label, value))
}

/// Number of terminal lines the active prompt occupies (0 when none; the save
/// confirmation adds a warning line).
fn prompt_lines(app: &App) -> u16 {
    match app.state.prompt {
        Prompt::None => 0,
        Prompt::ConfirmSave => 2,
        _ => 1,
    }
}

/// Render the active prompt as a bottom input bar (label + masked input + hint),
/// with the lossy-field warning line above it for `ConfirmSave`.
fn render_prompt(frame: &mut Frame, app: &App, area: Rect) {
    if app.state.prompt == Prompt::None || area.height == 0 {
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    if app.state.prompt == Prompt::ConfirmSave {
        lines.push(Line::from(Span::styled(
            LOSSY_SAVE_WARNING,
            Style::default().fg(Color::Yellow),
        )));
    }

    let (label, hint) = prompt_label_and_hint(&app.state.prompt);
    let displayed = if app.state.masked_input {
        "*".repeat(app.state.input.chars().count())
    } else {
        app.state.input.clone()
    };
    lines.push(Line::from(vec![
        Span::styled(label, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::raw(displayed),
        Span::raw("  "),
        Span::styled(hint, Style::default().fg(Color::DarkGray)),
    ]));

    frame.render_widget(Paragraph::new(lines), area);
}

/// The input-bar label and right-aligned hint for each prompt variant.
fn prompt_label_and_hint(prompt: &Prompt) -> (&'static str, &'static str) {
    match prompt {
        Prompt::None => ("", ""),
        Prompt::AddEntryTitle => ("Title:", "Enter = next · Esc = cancel"),
        Prompt::AddEntryUsername { .. } => ("Username:", "Enter = next · Esc = cancel"),
        Prompt::AddEntryPassword { .. } => ("Password:", "Enter = create · Esc = cancel"),
        Prompt::AddGroupName => ("Group name:", "Enter = create · Esc = cancel"),
        Prompt::EditField { field, .. } => (edit_label(field), "Enter = save · Esc = cancel"),
        Prompt::ConfirmDeleteEntry { .. } => (
            "Delete entry? (y/N):",
            "y = delete · any other key = cancel",
        ),
        Prompt::ConfirmDeleteGroup { .. } => (
            "Delete group? (y/N):",
            "y = delete · any other key = cancel",
        ),
        Prompt::ConfirmSave => ("Save database? (y/N):", "y = save · any other key = cancel"),
        Prompt::PluginCommand { .. } => ("Plugin command:", "Enter = run · Esc = cancel"),
    }
}

fn edit_label(field: &EntryField) -> &'static str {
    match field {
        EntryField::Title => "Edit title:",
        EntryField::UserName => "Edit username:",
        EntryField::Password => "Edit password:",
        EntryField::Url => "Edit URL:",
        EntryField::Notes => "Edit notes:",
        EntryField::Custom(_) => "Edit field:",
    }
}

fn render_status(frame: &mut Frame, app: &App, area: Rect) {
    let locked = app.state.db.is_none();
    let lock_label = if locked { "LOCKED" } else { "unlocked" };
    let lock_style = if locked {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Green)
    };

    let mut spans = vec![
        Span::styled(lock_label, lock_style),
        Span::raw(" · "),
        Span::raw(app.config.location.short_label()),
        Span::raw(format!(" · {} entries", app.state.entry_count())),
    ];

    let hint = match app.busy_label() {
        Some(busy) => busy.to_string(),
        None => match app.status() {
            Status::Idle => String::new(),
            Status::Info(info) => info.clone(),
            Status::Copy { copied_at, timeout } => {
                let remaining = timeout.saturating_sub(copied_at.elapsed());
                format!("copied — auto-clears in {}s", remaining.as_secs())
            }
        },
    };
    spans.push(Span::raw("   "));
    spans.push(Span::styled(hint, Style::default().fg(Color::DarkGray)));

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Render the contextual key-hint bar, dropping tips that do not fit.
fn render_key_bar(frame: &mut Frame, app: &App, area: Rect) {
    let key_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let label_style = Style::default().fg(Color::Gray);
    let sep_style = Style::default().fg(Color::DarkGray);

    let mut spans: Vec<Span> = Vec::new();
    let mut used = 0usize;
    let width = area.width as usize;
    for (index, (key, label)) in app.key_tips().into_iter().enumerate() {
        let piece_width = key.chars().count() + 1 + label.chars().count();
        let separator_width = if index == 0 { 0 } else { 3 };
        if used + separator_width + piece_width > width {
            break;
        }
        if index > 0 {
            spans.push(Span::styled(" │ ", sep_style));
        }
        spans.push(Span::styled(key, key_style));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(label, label_style));
        used += separator_width + piece_width;
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Render the plugin picker as a centered overlay.
fn render_plugin_menu(frame: &mut Frame, app: &App) {
    let Some(menu) = &app.state.plugin_menu else {
        return;
    };
    let items: Vec<ListItem> = menu
        .paths
        .iter()
        .map(|path| {
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("?");
            ListItem::new(name.to_string())
        })
        .collect();

    let height = (items.len() as u16 + 2).min(frame.area().height).max(3);
    let area = centered(frame.area(), 60, height);
    let list = List::new(items)
        .block(Block::bordered().title("Plugins — Enter run · Esc close"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default();
    state.select(Some(menu.index));
    frame.render_stateful_widget(list, area, &mut state);
}

/// Render a plugin's output in a centered modal (dismissed by any key).
fn render_plugin_result(frame: &mut Frame, result: &str) {
    let lines: Vec<Line> = result
        .lines()
        .map(|line| Line::from(line.to_string()))
        .collect();
    let height = (lines.len() as u16 + 2).min(frame.area().height).max(3);
    let width = frame.area().width.min(72);
    let area = centered(frame.area(), width, height);
    let paragraph =
        Paragraph::new(lines).block(Block::bordered().title("Plugin result — any key to close"));
    frame.render_widget(paragraph, area);
}

/// Render the save-conflict modal: reload the remote or overwrite it.
fn render_conflict(frame: &mut Frame, label: &str) {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let lines = vec![
        Line::from(format!(
            "{label} changed on the remote since you unlocked it."
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("R", bold),
            Span::raw("  reload remote — discards local edits"),
        ]),
        Line::from(vec![
            Span::styled("O", bold),
            Span::raw("  overwrite remote — keeps local edits"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Esc  dismiss (local edits stay in memory)",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let width = frame.area().width.min(72);
    let height = (lines.len() as u16 + 2).min(frame.area().height);
    let area = centered(frame.area(), width, height);
    let paragraph = Paragraph::new(lines)
        .block(Block::bordered().title("Save conflict — R reload · O overwrite"));
    frame.render_widget(paragraph, area);
}

/// A rectangle centered within `area`, clamped to the available size.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width, height)
}
