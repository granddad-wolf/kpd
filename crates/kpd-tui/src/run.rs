//! Terminal lifecycle and the main event loop for `kpd-tui`.

use std::io;
use std::time::Duration;

use crossterm::cursor;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};

use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::app::{App, Control};
use crate::ui;
use crate::{AppConfig, TuiError};

/// How long [`event::poll`] blocks before timing out. On timeout we redraw, so
/// the copy countdown in the status bar stays fresh without busy-waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Run the interactive TUI until the user quits.
///
/// # Errors
///
/// Returns [`TuiError::Terminal`] if raw mode / the alternate screen / the
/// terminal cannot be set up, or if drawing or reading events fails.
pub fn run(config: AppConfig) -> Result<(), TuiError> {
    let mut stdout = io::stdout();
    terminal::enable_raw_mode().map_err(terminal_error)?;
    if let Err(err) = crossterm::execute!(stdout, EnterAlternateScreen, cursor::Hide) {
        let _ = terminal::disable_raw_mode();
        return Err(terminal_error(err));
    }

    // From here on, any panic must restore the terminal before unwinding.
    install_panic_hook();

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(terminal_error)?;

    let result = event_loop(&mut terminal, &config);

    // Restore the terminal on every exit path (success, error, or after the
    // panic hook already ran during unwinding).
    restore_terminal();

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    config: &AppConfig,
) -> Result<(), TuiError> {
    let mut app = App::new(config.clone());

    loop {
        terminal
            .draw(|frame| ui::render(frame, &app))
            .map_err(terminal_error)?;

        if !event::poll(POLL_INTERVAL).map_err(terminal_error)? {
            continue;
        }

        match event::read().map_err(terminal_error)? {
            Event::Key(key) => {
                // Act on press and repeat alike (so held keys keep navigating);
                // ignore release events.
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                if app.handle_key(&key) == Control::Quit {
                    return Ok(());
                }
                // Cloud fetch/save blocks on the network; draw the busy message
                // first so the wait is visible, then run the deferred work.
                if app.is_busy() {
                    terminal
                        .draw(|frame| ui::render(frame, &app))
                        .map_err(terminal_error)?;
                    app.run_pending();
                }
            }
            // Ratatui re-reads the size during the next draw, so a resize just
            // needs the loop to redraw.
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

/// Restore the terminal after a panic, chaining to any pre-existing hook.
fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        original(info);
    }));
}

fn restore_terminal() {
    let _ = terminal::disable_raw_mode();
    let mut out = io::stdout();
    let _ = crossterm::execute!(out, LeaveAlternateScreen, cursor::Show);
}

fn terminal_error(err: io::Error) -> TuiError {
    TuiError::Terminal(err.to_string())
}
