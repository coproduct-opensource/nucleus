//! Web frontend for the exposure playground.
//!
//! Compiles the same ratatui UI to WASM via ratzilla's DomBackend.
//! All app state, demo data, and rendering logic is shared with the
//! native TUI via the `exposure-playground` library crate.

use std::cell::RefCell;
use std::rc::Rc;

use exposure_playground::app::{App, MeetSide, Screen};
use exposure_playground::ui;
use ratzilla::event::KeyCode;
use ratzilla::ratatui::Terminal;
use ratzilla::{DomBackend, WebRenderer};

fn main() {
    let backend = DomBackend::new().expect("failed to create DomBackend");
    let mut terminal = Terminal::new(backend).expect("failed to create terminal");

    let app = Rc::new(RefCell::new(App::new()));

    // Key event handler
    let app_key = Rc::clone(&app);
    terminal.on_key_event(move |key_event| {
        let mut app = app_key.borrow_mut();
        let code = key_event.code;

        // Global quit is a no-op in web (no terminal to restore)
        // Instead, 'q' on the main screen shows help
        if code == KeyCode::Char('q') && app.screen == Screen::UninhabitableState {
            app.screen = Screen::Help;
            return;
        }

        match app.screen {
            Screen::UninhabitableState => handle_uninhabitable(&mut app, code),
            Screen::TraceChain => handle_trace(&mut app, code),
            Screen::Attacks => handle_attacks(&mut app, code),
            Screen::Matrix => handle_matrix(&mut app, code),
            Screen::Hasse => handle_hasse(&mut app, code),
            Screen::Meet => handle_meet(&mut app, code),
            Screen::ChainBuilder => handle_chain_builder(&mut app, code),
            Screen::DelegationForest => handle_delegation_forest(&mut app, code),
            Screen::Help => handle_help(&mut app, code),
        }
    });

    // Render loop
    let app_draw = Rc::clone(&app);
    terminal.draw_web(move |f| {
        let app = app_draw.borrow();
        ui::draw(f, &app);
    });
}

fn handle_uninhabitable(app: &mut App, key: KeyCode) {
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
        KeyCode::Char('d') => app.screen = Screen::DelegationForest,
        KeyCode::Char('?') => app.screen = Screen::Help,
        KeyCode::Up | KeyCode::Char('k') => app.prev_capability(),
        KeyCode::Down | KeyCode::Char('j') => app.next_capability(),
        KeyCode::Left | KeyCode::Char('h') => app.decrease_capability(),
        KeyCode::Right | KeyCode::Char('l') => app.increase_capability(),
        KeyCode::Enter | KeyCode::Char(' ') => app.toggle_capability(),
        _ => {}
    }
}

fn handle_trace(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('e') => app.extend_chain(),
        KeyCode::Char('v') => app.verify_chain(),
        KeyCode::Char('r') => app.reset_chain(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::UninhabitableState,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_attacks(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up | KeyCode::Char('k') => app.prev_attack(),
        KeyCode::Down | KeyCode::Char('j') => app.next_attack(),
        KeyCode::Enter | KeyCode::Char(' ') => app.run_attack(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::UninhabitableState,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_matrix(app: &mut App, key: KeyCode) {
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
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::UninhabitableState,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_hasse(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Right | KeyCode::Char('l') => app.hasse_state.next_node(),
        KeyCode::Left | KeyCode::Char('h') => app.hasse_state.prev_node(),
        KeyCode::Up | KeyCode::Char('k') => app.hasse_state.prev_node(),
        KeyCode::Down | KeyCode::Char('j') => app.hasse_state.next_node(),
        KeyCode::Char('m') => app.hasse_state.toggle_meet_mode(),
        KeyCode::Enter | KeyCode::Char(' ') => {
            if app.hasse_state.meet_mode {
                if let Some(_result) = app.hasse_state.select_meet_second() {
                    app.screen = Screen::Meet;
                }
            }
        }
        KeyCode::Esc | KeyCode::Backspace => {
            if app.hasse_state.meet_mode {
                app.hasse_state.meet_mode = false;
                app.hasse_state.meet_first = None;
            } else {
                app.screen = Screen::UninhabitableState;
            }
        }
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_meet(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Tab => app.meet_playground.toggle_side(),
        KeyCode::Char('1') => app.meet_playground.selecting = MeetSide::Left,
        KeyCode::Char('2') => app.meet_playground.selecting = MeetSide::Right,
        KeyCode::Up | KeyCode::Char('k') => app.meet_playground.prev_preset(),
        KeyCode::Down | KeyCode::Char('j') => app.meet_playground.next_preset(),
        KeyCode::Enter | KeyCode::Char(' ') => app.meet_playground.compute_meet(),
        KeyCode::Char('p') => app.meet_playground.next_preset(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::UninhabitableState,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_chain_builder(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('e') => app.chain_builder.add_link(),
        KeyCode::Char('d') => app.chain_builder.remove_last(),
        KeyCode::Char('p') => app.chain_builder.cycle_preset(),
        KeyCode::Char('v') => app.chain_builder.compute_ceiling(),
        KeyCode::Up | KeyCode::Char('k') => app.chain_builder.prev_link(),
        KeyCode::Down | KeyCode::Char('j') => app.chain_builder.next_link(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::UninhabitableState,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_delegation_forest(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Left | KeyCode::Char('h') => app.delegation_forest.go_to_parent(),
        KeyCode::Right | KeyCode::Char('l') => app.delegation_forest.go_to_first_child(),
        KeyCode::Down | KeyCode::Char('j') => app.delegation_forest.go_to_next_sibling(),
        KeyCode::Up | KeyCode::Char('k') => app.delegation_forest.go_to_prev_sibling(),
        KeyCode::Char('a') => app.delegation_forest.add_child_default(),
        KeyCode::Char('x') => app.delegation_forest.remove_selected(),
        KeyCode::Char('p') => app.delegation_forest.cycle_preset(),
        KeyCode::Char('e') => app.delegation_forest.attempt_escalation(),
        KeyCode::Char('c') => app.delegation_forest.toggle_comparison(),
        KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::UninhabitableState,
        KeyCode::Char('?') => app.screen = Screen::Help,
        _ => {}
    }
}

fn handle_help(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('?') | KeyCode::Enter => {
            app.screen = Screen::UninhabitableState;
        }
        _ => {}
    }
}
