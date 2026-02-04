//! UI rendering for the playground.

use lattice_guard::{CapabilityLevel, Operation, PermissionLattice, TrifectaRisk};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        canvas::{Canvas, Line as CanvasLine},
        Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Wrap,
    },
    Frame,
};

use crate::app::{App, MeetSide, Screen, SelectedCapability};
use crate::demo::{get_hasse_edges, preset_descriptions, ATTACK_SCENARIOS, PERMISSION_PRESETS};

/// Main draw function that dispatches to the current screen.
pub fn draw(f: &mut Frame, app: &App) {
    match app.screen {
        Screen::Trifecta => draw_trifecta(f, app),
        Screen::TraceChain => draw_trace_chain(f, app),
        Screen::Attacks => draw_attacks(f, app),
        Screen::Matrix => draw_capability_matrix(f, app),
        Screen::Hasse => draw_hasse_diagram(f, app),
        Screen::Meet => draw_meet_playground(f, app),
        Screen::ChainBuilder => draw_chain_builder(f, app),
        Screen::Help => {
            draw_trifecta(f, app);
            draw_help_popup(f);
        }
    }
}

/// Draw the main trifecta detection screen.
fn draw_trifecta(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(7), // Trifecta indicator
            Constraint::Min(10),   // Capabilities
            Constraint::Length(5), // Obligations
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("Trifecta Guard Playground")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Trifecta indicator
    draw_trifecta_indicator(f, app, chunks[1]);

    // Capabilities
    draw_capabilities(f, app, chunks[2]);

    // Obligations
    draw_obligations(f, app, chunks[3]);

    // Footer
    draw_footer(f, app, chunks[4]);
}

/// Draw the three-panel trifecta indicator.
fn draw_trifecta_indicator(f: &mut Frame, app: &App, area: Rect) {
    let (has_private, has_untrusted, has_exfil) = app.active_components();
    let risk = app.trifecta_risk();

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(area);

    // Private data box
    let private_style = if has_private {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let private_box = Paragraph::new(vec![
        Line::from(Span::styled("PRIVATE", private_style)),
        Line::from(Span::styled("DATA", private_style)),
        Line::from(Span::styled(
            if has_private { "[ON]" } else { "[OFF]" },
            private_style,
        )),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title("1"));
    f.render_widget(private_box, chunks[0]);

    // Plus sign
    // Plus signs are implied by the layout

    // Untrusted content box
    let untrusted_style = if has_untrusted {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let untrusted_box = Paragraph::new(vec![
        Line::from(Span::styled("UNTRUSTED", untrusted_style)),
        Line::from(Span::styled("CONTENT", untrusted_style)),
        Line::from(Span::styled(
            if has_untrusted { "[ON]" } else { "[OFF]" },
            untrusted_style,
        )),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title("2"));
    f.render_widget(untrusted_box, chunks[1]);

    // Exfiltration box
    let exfil_style = if has_exfil {
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let exfil_box = Paragraph::new(vec![
        Line::from(Span::styled("EXFIL", exfil_style)),
        Line::from(Span::styled("VECTOR", exfil_style)),
        Line::from(Span::styled(
            if has_exfil { "[ON]" } else { "[OFF]" },
            exfil_style,
        )),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title("3"));
    f.render_widget(exfil_box, chunks[2]);

    // Status box
    let (status_text, status_style) = match risk {
        TrifectaRisk::None => (
            "SAFE",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        TrifectaRisk::Low => ("LOW RISK", Style::default().fg(Color::Green)),
        TrifectaRisk::Medium => ("MEDIUM", Style::default().fg(Color::Yellow)),
        TrifectaRisk::Complete => (
            "GATED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    };
    let status_box = Paragraph::new(vec![
        Line::from(Span::styled("=", Style::default().fg(Color::White))),
        Line::from(Span::styled(status_text, status_style)),
        Line::from(Span::styled(
            if risk == TrifectaRisk::Complete {
                "Auto-gated"
            } else {
                ""
            },
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(status_box, chunks[3]);
}

/// Draw the capabilities list.
fn draw_capabilities(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Capabilities (↑↓ to select, ←→ to change) ");

    let items: Vec<ListItem> = SelectedCapability::all()
        .iter()
        .map(|cap| {
            let level = app.get_capability(*cap);
            let is_selected = *cap == app.selected_capability;

            let level_str = match level {
                CapabilityLevel::Never => "Never  ",
                CapabilityLevel::LowRisk => "LowRisk",
                CapabilityLevel::Always => "Always ",
            };

            let level_color = match level {
                CapabilityLevel::Never => Color::DarkGray,
                CapabilityLevel::LowRisk => Color::Yellow,
                CapabilityLevel::Always => Color::Green,
            };

            // Highlight if this is a trifecta component
            let component_marker = match cap.trifecta_component() {
                Some(crate::app::TrifectaComponent::PrivateData) => " [P]",
                Some(crate::app::TrifectaComponent::UntrustedContent) => " [U]",
                Some(crate::app::TrifectaComponent::Exfiltration) => " [E]",
                None => "    ",
            };

            let style = if is_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let line = Line::from(vec![
                Span::styled(if is_selected { "▶ " } else { "  " }, style),
                Span::styled(format!("{:12}", cap.name()), style),
                Span::styled(level_str, style.fg(level_color)),
                Span::styled(component_marker, style.fg(Color::Cyan)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

/// Draw the obligations panel.
fn draw_obligations(f: &mut Frame, app: &App, area: Rect) {
    let obligations = app.obligations();
    let risk = app.trifecta_risk();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Obligations ");

    let content = if obligations.approvals.is_empty() {
        if risk == TrifectaRisk::Complete {
            // This shouldn't happen with proper enforcement
            Text::from(Line::from(vec![
                Span::styled("ERROR: ", Style::default().fg(Color::Red)),
                Span::raw("Trifecta complete but no obligations?"),
            ]))
        } else {
            Text::from(Line::from(Span::styled(
                "(none - configuration is safe)",
                Style::default().fg(Color::Green),
            )))
        }
    } else {
        let mut lines = vec![Line::from(Span::styled(
            "The nucleus operator ν automatically added:",
            Style::default().fg(Color::Yellow),
        ))];

        for op in &obligations.approvals {
            let op_name = match op {
                Operation::GitPush => "git_push",
                Operation::CreatePr => "create_pr",
                Operation::RunBash => "run_bash",
                _ => "unknown",
            };
            lines.push(Line::from(vec![
                Span::styled("  ⚠ ", Style::default().fg(Color::Red)),
                Span::styled(op_name, Style::default().fg(Color::White)),
                Span::styled(" requires APPROVAL", Style::default().fg(Color::Red)),
            ]));
        }

        Text::from(lines)
    };

    let paragraph = Paragraph::new(content).block(block);
    f.render_widget(paragraph, area);
}

/// Draw the footer with navigation hints.
fn draw_footer(f: &mut Frame, _app: &App, area: Rect) {
    let presets = preset_descriptions();
    let preset_hints: Vec<Span> = presets
        .iter()
        .map(|(key, _desc)| Span::styled(format!("[{}] ", key), Style::default().fg(Color::Cyan)))
        .collect();

    let mut footer_spans = preset_hints;
    footer_spans.push(Span::styled(
        "[6]matrix ",
        Style::default().fg(Color::Green),
    ));
    footer_spans.push(Span::styled(
        "[t]race ",
        Style::default().fg(Color::Magenta),
    ));
    footer_spans.push(Span::styled("[c]hain ", Style::default().fg(Color::Yellow)));
    footer_spans.push(Span::styled("[?]help ", Style::default().fg(Color::White)));
    footer_spans.push(Span::styled("[q]uit", Style::default().fg(Color::DarkGray)));

    let footer = Paragraph::new(Line::from(footer_spans))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, area);
}

/// Draw the SPIFFE trace chain screen.
fn draw_trace_chain(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(10),   // Chain visualization
            Constraint::Length(5), // Ceiling
            Constraint::Length(3), // Status
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("SPIFFE Trace Chain")
        .style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Chain visualization
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Delegation Chain ");

    let mut lines = vec![];
    for (i, link) in app.trace_chain.links.iter().enumerate() {
        let indent: String = "  ".repeat(i);
        let connector = if i == 0 {
            "".to_string()
        } else {
            "└─► ".to_string()
        };
        let spiffe_id = link.spiffe_id.clone();

        lines.push(Line::from(vec![
            Span::raw(indent.clone()),
            Span::styled(connector, Style::default().fg(Color::DarkGray)),
            Span::styled(spiffe_id, Style::default().fg(Color::Cyan)),
        ]));

        let perms_label = if link.permissions.description.contains("ermissive") {
            "PERMISSIVE"
        } else if link.permissions.description.contains("odegen") {
            "CODEGEN"
        } else {
            "RESTRICTED"
        };
        let sub_indent = if i == 0 {
            "  ".to_string()
        } else {
            "    ".to_string()
        };
        lines.push(Line::from(vec![
            Span::raw(indent.clone()),
            Span::raw(sub_indent.clone()),
            Span::styled("perms: ", Style::default().fg(Color::DarkGray)),
            Span::styled(perms_label, Style::default().fg(Color::Yellow)),
        ]));

        lines.push(Line::from(vec![
            Span::raw(indent.clone()),
            Span::raw(sub_indent),
            Span::styled("drand: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("#{}", link.drand_round),
                Style::default().fg(Color::Green),
            ),
        ]));

        lines.push(Line::from(""));
    }

    let chain_para = Paragraph::new(lines).block(block);
    f.render_widget(chain_para, chunks[1]);

    // Ceiling theorem
    let ceiling = app.trace_chain.ceiling();
    let ceiling_block = Block::default()
        .borders(Borders::ALL)
        .title(" Ceiling Theorem ");
    let ceiling_label = match &ceiling {
        Some(c) if c.description.contains("ermissive") => "PERMISSIVE",
        Some(c) if c.description.contains("odegen") => "CODEGEN",
        Some(_) => "RESTRICTED",
        None => "EMPTY CHAIN",
    };
    let ceiling_text = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            "effective_perms(agent) ≤ meet(trace_chain)",
            Style::default().fg(Color::White),
        )]),
        Line::from(vec![
            Span::styled("Current ceiling: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                ceiling_label,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ])
    .block(ceiling_block);
    f.render_widget(ceiling_text, chunks[2]);

    // Status
    if let Some(ref status) = app.chain_status {
        let status_para = Paragraph::new(status.as_str())
            .style(Style::default().fg(Color::Green))
            .alignment(Alignment::Center);
        f.render_widget(status_para, chunks[3]);
    }

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[e]xtend ", Style::default().fg(Color::Cyan)),
        Span::styled("[v]erify ", Style::default().fg(Color::Green)),
        Span::styled("[r]eset ", Style::default().fg(Color::Yellow)),
        Span::styled("[Esc]back ", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, chunks[4]);
}

/// Draw the attack simulator screen.
fn draw_attacks(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // Title
            Constraint::Length(12), // Attack list
            Constraint::Min(8),     // Result
            Constraint::Length(3),  // Footer
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("Attack Simulator")
        .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Attack list
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Select Attack ");

    let items: Vec<ListItem> = ATTACK_SCENARIOS
        .iter()
        .enumerate()
        .map(|(i, scenario)| {
            let is_selected = i == app.selected_attack;
            let style = if is_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(if is_selected { "▶ " } else { "  " }, style),
                Span::styled(scenario.name, style.fg(Color::Red)),
            ]))
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, chunks[1]);

    // Result
    let result_block = Block::default().borders(Borders::ALL).title(" Result ");

    let scenario = &ATTACK_SCENARIOS[app.selected_attack];

    let result_content = if let Some(ref result) = app.attack_result {
        let status_style = if result.blocked {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        };

        vec![
            Line::from(vec![
                Span::styled("Attack: ", Style::default().fg(Color::DarkGray)),
                Span::styled(scenario.name, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    if result.blocked {
                        "██ BLOCKED"
                    } else {
                        "!! ALLOWED"
                    },
                    status_style,
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Defense: ",
                Style::default().fg(Color::Cyan),
            )]),
            Line::from(Span::styled(
                &result.defense,
                Style::default().fg(Color::White),
            )),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled("Attack: ", Style::default().fg(Color::DarkGray)),
                Span::styled(scenario.name, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Description: ",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(Span::styled(
                scenario.description,
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Press [Enter] to run attack",
                Style::default().fg(Color::Yellow),
            )),
        ]
    };

    let result_para = Paragraph::new(result_content)
        .block(result_block)
        .wrap(Wrap { trim: true });
    f.render_widget(result_para, chunks[2]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[↑↓]select ", Style::default().fg(Color::Cyan)),
        Span::styled("[Enter]run ", Style::default().fg(Color::Green)),
        Span::styled("[Esc]back ", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, chunks[3]);
}

/// Draw the help popup.
fn draw_help_popup(f: &mut Frame) {
    let area = centered_rect(60, 70, f.area());

    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help ")
        .style(Style::default().bg(Color::Black));

    let help_text = vec![
        Line::from(Span::styled(
            "Trifecta Guard Playground",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "The Lethal Trifecta",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Three capabilities that together enable prompt injection:"),
        Line::from("  1. Private data access (read files)"),
        Line::from("  2. Untrusted content (web fetch/search)"),
        Line::from("  3. Exfiltration vector (git push, bash, PR)"),
        Line::from(""),
        Line::from(Span::styled(
            "Screens",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  t/Tab  Trace chain view"),
        Line::from("  a      Attack simulator"),
        Line::from("  m/6    Capability matrix"),
        Line::from("  H      Hasse diagram (lattice visualization)"),
        Line::from("  M      Meet playground (compute meets)"),
        Line::from("  c      Chain builder"),
        Line::from(""),
        Line::from(Span::styled(
            "Navigation",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  ↑/↓ j/k    Select / navigate"),
        Line::from("  ←/→ h/l    Change level / navigate"),
        Line::from("  Enter      Confirm / compute"),
        Line::from("  1-5        Load preset"),
        Line::from("  q          Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "The Math",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("When trifecta is complete, the nucleus operator ν"),
        Line::from("adds approval obligations. Meet (∧) computes the"),
        Line::from("greatest lower bound of two permission sets."),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(help_text)
        .block(block)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

/// Helper to create a centered rect.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Draw the capability matrix screen.
fn draw_capability_matrix(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(15),   // Matrix table
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("Capability Matrix")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Build the matrix table
    let presets = &*PERMISSION_PRESETS;

    // Header row
    let header_cells =
        std::iter::once(Cell::from("Capability")).chain(presets.iter().map(|(name, _)| {
            Cell::from(*name).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Capability rows - 11 capabilities
    let capability_names = [
        "read_files",
        "write_files",
        "edit_files",
        "run_bash",
        "glob_search",
        "grep_search",
        "web_search",
        "web_fetch",
        "git_commit",
        "git_push",
        "create_pr",
    ];

    let rows: Vec<Row> = capability_names
        .iter()
        .enumerate()
        .map(|(i, cap_name)| {
            let is_selected = i == app.matrix_selected_row;
            let row_style = if is_selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            let cells =
                std::iter::once(Cell::from(*cap_name).style(Style::default().fg(Color::White)))
                    .chain(presets.iter().map(|(_, perms)| {
                        let level = get_capability_level(&perms.capabilities, cap_name);
                        let (symbol, color) = match level {
                            CapabilityLevel::Never => ("⊥", Color::DarkGray),
                            CapabilityLevel::LowRisk => ("◐", Color::Yellow),
                            CapabilityLevel::Always => ("⊤", Color::Green),
                        };
                        Cell::from(symbol).style(Style::default().fg(color))
                    }));

            Row::new(cells).style(row_style)
        })
        .collect();

    // Calculate column widths
    let mut widths = vec![Constraint::Length(12)]; // capability name
    for _ in 0..presets.len() {
        widths.push(Constraint::Length(12));
    }

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Presets × Capabilities "),
    );

    f.render_widget(table, chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[↑↓]select ", Style::default().fg(Color::Cyan)),
        Span::styled("[m]eet ", Style::default().fg(Color::Green)),
        Span::styled("[h]asse ", Style::default().fg(Color::Magenta)),
        Span::styled("[Esc]back ", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, chunks[2]);
}

/// Get capability level by name from a CapabilityLattice.
fn get_capability_level(caps: &lattice_guard::CapabilityLattice, name: &str) -> CapabilityLevel {
    match name {
        "read_files" => caps.read_files,
        "write_files" => caps.write_files,
        "edit_files" => caps.edit_files,
        "run_bash" => caps.run_bash,
        "glob_search" => caps.glob_search,
        "grep_search" => caps.grep_search,
        "web_search" => caps.web_search,
        "web_fetch" => caps.web_fetch,
        "git_commit" => caps.git_commit,
        "git_push" => caps.git_push,
        "create_pr" => caps.create_pr,
        _ => CapabilityLevel::Never,
    }
}

/// Draw the Hasse diagram screen.
fn draw_hasse_diagram(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(15),   // Diagram
            Constraint::Length(5), // Details panel
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Title
    let title_text = if app.hasse_state.meet_mode {
        "Hasse Diagram [MEET MODE - select second node]"
    } else {
        "Hasse Diagram"
    };
    let title = Paragraph::new(title_text)
        .style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    let presets = &*PERMISSION_PRESETS;
    let edges = get_hasse_edges(presets);

    // Draw the diagram using Canvas
    let canvas = Canvas::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Partial Order "),
        )
        .x_bounds([0.0, 100.0])
        .y_bounds([0.0, 100.0])
        .paint(|ctx| {
            // Calculate node positions in a simple layout
            // Top: PERMISSIVE, Bottom: RESTRICTIVE, others in between
            let node_positions = calculate_node_positions(presets.len());

            // Draw edges first (behind nodes)
            for (child, parent) in &edges {
                let (x1, y1) = node_positions[*child];
                let (x2, y2) = node_positions[*parent];
                ctx.draw(&CanvasLine {
                    x1,
                    y1,
                    x2,
                    y2,
                    color: Color::DarkGray,
                });
            }

            // Draw nodes
            for (i, (name, _perms)) in presets.iter().enumerate() {
                let (x, y) = node_positions[i];
                let is_selected = i == app.hasse_state.selected_node;
                let is_meet_first = app.hasse_state.meet_first == Some(i);

                let color = if is_meet_first {
                    Color::Yellow
                } else if is_selected {
                    Color::Cyan
                } else {
                    Color::White
                };

                // Draw node label
                ctx.print(x, y, Span::styled(*name, Style::default().fg(color)));
            }
        });

    f.render_widget(canvas, chunks[1]);

    // Details panel
    let selected_idx = app.hasse_state.selected_node;
    let (name, perms) = &presets[selected_idx];

    let detail_lines = vec![
        Line::from(vec![
            Span::styled("Selected: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                *name,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Trifecta: ", Style::default().fg(Color::DarkGray)),
            if perms.is_trifecta_vulnerable() {
                Span::styled("VULNERABLE (gated)", Style::default().fg(Color::Red))
            } else {
                Span::styled("safe", Style::default().fg(Color::Green))
            },
        ]),
    ];

    let details = Paragraph::new(detail_lines)
        .block(Block::default().borders(Borders::ALL).title(" Details "));
    f.render_widget(details, chunks[2]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[hjkl]navigate ", Style::default().fg(Color::Cyan)),
        Span::styled("[m]eet mode ", Style::default().fg(Color::Yellow)),
        Span::styled("[Enter]select ", Style::default().fg(Color::Green)),
        Span::styled("[Esc]back ", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, chunks[3]);
}

/// Calculate node positions for Hasse diagram.
fn calculate_node_positions(count: usize) -> Vec<(f64, f64)> {
    // Simple layout: distribute nodes in a grid-like pattern
    // PERMISSIVE at top (index 0), RESTRICTIVE at bottom (index 1)
    // Others distributed in the middle

    let mut positions = Vec::with_capacity(count);

    if count == 0 {
        return positions;
    }

    // PERMISSIVE at top center
    positions.push((50.0, 90.0));

    if count > 1 {
        // RESTRICTIVE at bottom center
        positions.push((50.0, 10.0));
    }

    // Distribute remaining nodes in middle rows
    if count > 2 {
        let middle_count = count - 2;
        let rows = ((middle_count as f64).sqrt().ceil() as usize).max(1);
        let per_row = middle_count.div_ceil(rows);

        for i in 0..middle_count {
            let row = i / per_row;
            let col = i % per_row;
            let cols_in_row = if row == rows - 1 {
                middle_count - row * per_row
            } else {
                per_row
            };

            let y = 80.0 - (row as f64 + 1.0) * (70.0 / (rows + 1) as f64);
            let x = if cols_in_row == 1 {
                50.0
            } else {
                20.0 + (col as f64) * (60.0 / (cols_in_row - 1) as f64)
            };

            positions.push((x, y));
        }
    }

    positions
}

/// Draw the meet playground screen.
fn draw_meet_playground(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // Title
            Constraint::Length(10), // Left and Right panels
            Constraint::Length(3),  // Meet operator
            Constraint::Min(10),    // Result panel
            Constraint::Length(3),  // Footer
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("Meet Playground (∧)")
        .style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Left and Right panels
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let presets = &*PERMISSION_PRESETS;

    // Left panel
    let left_selected = app.meet_playground.selecting == MeetSide::Left;
    let left_style = if left_selected {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let left_idx = app.meet_playground.left.unwrap_or(0);
    let (left_name, left_perms) = &presets[left_idx];

    let left_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Left {} ", if left_selected { "▶" } else { " " }))
        .border_style(left_style);

    let left_content = format_permission_summary(left_name, left_perms);
    let left_para = Paragraph::new(left_content).block(left_block);
    f.render_widget(left_para, panels[0]);

    // Right panel
    let right_selected = app.meet_playground.selecting == MeetSide::Right;
    let right_style = if right_selected {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let right_idx = app.meet_playground.right.unwrap_or(0);
    let (right_name, right_perms) = &presets[right_idx];

    let right_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(
            " Right {} ",
            if right_selected { "▶" } else { " " }
        ))
        .border_style(right_style);

    let right_content = format_permission_summary(right_name, right_perms);
    let right_para = Paragraph::new(right_content).block(right_block);
    f.render_widget(right_para, panels[1]);

    // Meet operator
    let meet_text = Paragraph::new("∧ (meet = greatest lower bound)")
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Center);
    f.render_widget(meet_text, chunks[2]);

    // Result panel
    let result_block = Block::default().borders(Borders::ALL).title(" Result ");

    let result_content = if let Some(ref result) = app.meet_playground.result {
        let mut lines = vec![
            Line::from(Span::styled(
                "COMPUTED MEET",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        // Show key differences
        lines.push(Line::from(vec![
            Span::styled("Trifecta: ", Style::default().fg(Color::DarkGray)),
            if result.is_trifecta_vulnerable() {
                Span::styled("VULNERABLE - exfil gated", Style::default().fg(Color::Red))
            } else {
                Span::styled("safe", Style::default().fg(Color::Green))
            },
        ]));

        // Show which capabilities were reduced
        let left_caps = &left_perms.capabilities;
        let right_caps = &right_perms.capabilities;
        let result_caps = &result.capabilities;

        let mut reduced = Vec::new();
        for cap in [
            "read_files",
            "write_files",
            "edit_files",
            "run_bash",
            "web_fetch",
            "git_push",
            "create_pr",
        ] {
            let l = get_capability_level(left_caps, cap);
            let r = get_capability_level(right_caps, cap);
            let res = get_capability_level(result_caps, cap);
            if res < l || res < r {
                reduced.push(cap);
            }
        }

        if !reduced.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Reduced capabilities:",
                Style::default().fg(Color::Yellow),
            )));
            for cap in reduced {
                lines.push(Line::from(format!("  • {}", cap)));
            }
        }

        lines
    } else {
        vec![Line::from(Span::styled(
            "Press [Enter] to compute meet",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let result_para = Paragraph::new(result_content).block(result_block);
    f.render_widget(result_para, chunks[3]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[Tab]switch ", Style::default().fg(Color::Cyan)),
        Span::styled("[↑↓]preset ", Style::default().fg(Color::Yellow)),
        Span::styled("[Enter]compute ", Style::default().fg(Color::Green)),
        Span::styled("[Esc]back ", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, chunks[4]);
}

/// Format a permission summary for display.
fn format_permission_summary(name: &str, perms: &PermissionLattice) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            name.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("read: {:?}", perms.capabilities.read_files)),
        Line::from(format!("web:  {:?}", perms.capabilities.web_fetch)),
        Line::from(format!("push: {:?}", perms.capabilities.git_push)),
        Line::from(format!("bash: {:?}", perms.capabilities.run_bash)),
    ]
}

/// Draw the chain builder screen.
fn draw_chain_builder(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(15),   // Chain visualization
            Constraint::Length(6), // Ceiling panel
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("SPIFFE Delegation Chain Builder")
        .style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    let presets = &*PERMISSION_PRESETS;

    // Chain visualization
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Delegation Chain ");

    let mut lines: Vec<Line> = vec![];

    for (i, link) in app.chain_builder.chain.iter().enumerate() {
        let is_selected = i == app.chain_builder.selected_link;
        let (preset_name, _perms) = &presets[link.preset_index];

        let style = if is_selected {
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        // Indent based on chain depth
        let indent: String = "  ".repeat(i);
        let connector = if i == 0 {
            "ROOT:".to_string()
        } else {
            "└─► LINK:".to_string()
        };

        lines.push(Line::from(vec![
            Span::styled(indent.clone(), style),
            Span::styled(connector, Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {} ", link.spiffe_id), style.fg(Color::Cyan)),
        ]));

        lines.push(Line::from(vec![
            Span::raw(format!("{}    ", indent)),
            Span::styled("perms: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("[{}]", preset_name), style.fg(Color::Yellow)),
        ]));

        if i < app.chain_builder.chain.len() - 1 {
            lines.push(Line::from(vec![Span::raw(format!("{}  │", indent))]));
            lines.push(Line::from(vec![Span::raw(format!("{}  ∧ meet", indent))]));
            lines.push(Line::from(vec![Span::raw(format!("{}  ▼", indent))]));
        }

        lines.push(Line::from(""));
    }

    let chain_para = Paragraph::new(lines).block(block);
    f.render_widget(chain_para, chunks[1]);

    // Ceiling panel
    let ceiling_block = Block::default()
        .borders(Borders::ALL)
        .title(" Ceiling Theorem ");

    let ceiling_content = if let Some(ref ceiling) = app.chain_builder.ceiling {
        vec![
            Line::from(vec![Span::styled(
                "effective_perms(agent) ≤ meet(trace_chain)",
                Style::default().fg(Color::White),
            )]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Computed ceiling: ", Style::default().fg(Color::DarkGray)),
                if ceiling.is_trifecta_vulnerable() {
                    Span::styled(
                        "TRIFECTA GATED",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled(
                        "SAFE",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    )
                },
            ]),
            Line::from(vec![
                Span::styled("  read: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:?}", ceiling.capabilities.read_files),
                    Style::default().fg(Color::White),
                ),
                Span::styled("  web: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:?}", ceiling.capabilities.web_fetch),
                    Style::default().fg(Color::White),
                ),
                Span::styled("  push: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:?}", ceiling.capabilities.git_push),
                    Style::default().fg(Color::White),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "Press [v] to verify/compute ceiling",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let ceiling_para = Paragraph::new(ceiling_content).block(ceiling_block);
    f.render_widget(ceiling_para, chunks[2]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[e]xtend ", Style::default().fg(Color::Cyan)),
        Span::styled("[d]elete ", Style::default().fg(Color::Red)),
        Span::styled("[p]reset ", Style::default().fg(Color::Yellow)),
        Span::styled("[v]erify ", Style::default().fg(Color::Green)),
        Span::styled("[↑↓]select ", Style::default().fg(Color::White)),
        Span::styled("[Esc]back ", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, chunks[3]);
}
