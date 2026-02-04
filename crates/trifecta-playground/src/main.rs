//! Trifecta Playground - Interactive TUI for demonstrating the Lethal Trifecta prevention system.
//!
//! This application provides a visual, interactive demonstration of how the
//! lattice-guard permission system prevents dangerous capability combinations.

use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};

mod app;
mod demo;
mod ui;

use app::{App, MeetSide, Screen};

fn main() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let mut app = App::new();
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = result {
        eprintln!("Error: {err:?}");
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        // Poll for events with timeout
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Global quit keys
                if key.code == KeyCode::Char('q')
                    || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    return Ok(());
                }

                // Handle input based on current screen
                match app.screen {
                    Screen::Trifecta => handle_trifecta_input(app, key.code),
                    Screen::TraceChain => handle_trace_input(app, key.code),
                    Screen::Attacks => handle_attacks_input(app, key.code),
                    Screen::Matrix => handle_matrix_input(app, key.code),
                    Screen::Hasse => handle_hasse_input(app, key.code),
                    Screen::Meet => handle_meet_input(app, key.code),
                    Screen::ChainBuilder => handle_chain_builder_input(app, key.code),
                    Screen::Help => handle_help_input(app, key.code),
                }
            }
        }
    }
}

fn handle_trifecta_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('1') => app.load_preset(0),
        KeyCode::Char('2') => app.load_preset(1),
        KeyCode::Char('3') => app.load_preset(2),
        KeyCode::Char('4') => app.load_preset(3),
        KeyCode::Char('5') => app.load_preset(4),
        KeyCode::Char('6') => app.screen = Screen::Matrix,
        KeyCode::Char('t') | KeyCode::Tab => app.screen = Screen::TraceChain,
        KeyCode::Char('a') => app.screen = Screen::Attacks,
        KeyCode::Char('m') => app.screen = Screen::Matrix,
        KeyCode::Char('H') => app.screen = Screen::Hasse,
        KeyCode::Char('M') => app.screen = Screen::Meet,
        KeyCode::Char('c') => app.screen = Screen::ChainBuilder,
        KeyCode::Char('?') => app.screen = Screen::Help,
        KeyCode::Up | KeyCode::Char('k') => app.prev_capability(),
        KeyCode::Down | KeyCode::Char('j') => app.next_capability(),
        KeyCode::Left | KeyCode::Char('h') => app.decrease_capability(),
        KeyCode::Right | KeyCode::Char('l') => app.increase_capability(),
        KeyCode::Enter | KeyCode::Char(' ') => app.toggle_capability(),
        _ => {}
    }
}

fn handle_trace_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('e') => app.extend_chain(),
        KeyCode::Char('v') => app.verify_chain(),
        KeyCode::Char('r') => app.reset_chain(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::Trifecta,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_attacks_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up | KeyCode::Char('k') => app.prev_attack(),
        KeyCode::Down | KeyCode::Char('j') => app.next_attack(),
        KeyCode::Enter | KeyCode::Char(' ') => app.run_attack(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::Trifecta,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_help_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('?') | KeyCode::Enter => {
            app.screen = Screen::Trifecta
        }
        _ => {}
    }
}

fn handle_matrix_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            if app.matrix_selected_row > 0 {
                app.matrix_selected_row -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.matrix_selected_row < 10 {
                app.matrix_selected_row += 1;
            }
        }
        KeyCode::Char('m') => app.screen = Screen::Meet,
        KeyCode::Char('h') => app.screen = Screen::Hasse,
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::Trifecta,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_hasse_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Right | KeyCode::Char('l') => app.hasse_state.next_node(),
        KeyCode::Left | KeyCode::Char('h') => app.hasse_state.prev_node(),
        KeyCode::Up | KeyCode::Char('k') => app.hasse_state.prev_node(),
        KeyCode::Down | KeyCode::Char('j') => app.hasse_state.next_node(),
        KeyCode::Char('m') => app.hasse_state.toggle_meet_mode(),
        KeyCode::Enter | KeyCode::Char(' ') => {
            if app.hasse_state.meet_mode {
                // Compute meet between first and second selected nodes
                if let Some(_result) = app.hasse_state.select_meet_second() {
                    // Could show result in a popup or switch to Meet screen
                    app.screen = Screen::Meet;
                }
            }
        }
        KeyCode::Esc | KeyCode::Backspace => {
            if app.hasse_state.meet_mode {
                // Cancel meet mode
                app.hasse_state.meet_mode = false;
                app.hasse_state.meet_first = None;
            } else {
                app.screen = Screen::Trifecta;
            }
        }
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_meet_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Tab => app.meet_playground.toggle_side(),
        KeyCode::Char('1') => app.meet_playground.selecting = MeetSide::Left,
        KeyCode::Char('2') => app.meet_playground.selecting = MeetSide::Right,
        KeyCode::Up | KeyCode::Char('k') => app.meet_playground.prev_preset(),
        KeyCode::Down | KeyCode::Char('j') => app.meet_playground.next_preset(),
        KeyCode::Enter | KeyCode::Char(' ') => app.meet_playground.compute_meet(),
        KeyCode::Char('p') => {
            // Pick from preset list (just cycle for now)
            app.meet_playground.next_preset();
        }
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::Trifecta,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_chain_builder_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('e') => app.chain_builder.add_link(),
        KeyCode::Char('d') => app.chain_builder.remove_last(),
        KeyCode::Char('p') => app.chain_builder.cycle_preset(),
        KeyCode::Char('v') => app.chain_builder.compute_ceiling(),
        KeyCode::Up | KeyCode::Char('k') => app.chain_builder.prev_link(),
        KeyCode::Down | KeyCode::Char('j') => app.chain_builder.next_link(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::Trifecta,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}
