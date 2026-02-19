//! Delegation Forest TUI — visualizes hierarchical permission delegation.
//!
//! Shows an arena-based tree with effective permissions computed via
//! monotonic meet (delegate_to) at each edge. The structural differentiator
//! vs flat sandbox models: sub-pod permissions are always ≤ parent ceiling.

use lattice_guard::{CapabilityLevel, IncompatibilityConstraint, PermissionLattice, TrifectaRisk};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::DelegationForestState;
use crate::demo::PERMISSION_PRESETS;

/// Main draw function for the delegation forest screen.
pub fn draw(f: &mut Frame, state: &DelegationForestState, _area: Rect) {
    let show_sidebar = state.show_comparison;
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(12),   // Tree + optional sidebar
            Constraint::Length(5), // Node detail + edge delta
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Title bar
    let title = Paragraph::new(format!(
        "Delegation Forest                        depth:{}  nodes:{}",
        state.max_depth(),
        state.active_node_count()
    ))
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, main_chunks[0]);

    // Tree panel (with optional comparison sidebar)
    if show_sidebar {
        let h_split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(main_chunks[1]);
        draw_tree_panel(f, state, h_split[0]);
        draw_comparison_sidebar(f, h_split[1]);
    } else {
        draw_tree_panel(f, state, main_chunks[1]);
    }

    // Node detail + edge delta
    draw_detail_panel(f, state, main_chunks[2]);

    // Footer
    draw_footer(f, main_chunks[3]);
}

/// Draw the indented tree with connectors.
fn draw_tree_panel(f: &mut Frame, state: &DelegationForestState, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Delegation Tree ");

    let presets = &*PERMISSION_PRESETS;
    let visible = state.visible_nodes();
    let mut lines: Vec<Line> = Vec::new();

    for &node_id in &visible {
        let node = &state.nodes[node_id];
        if node.spiffe_id.is_empty() {
            continue;
        }
        let is_selected = node_id == state.selected_node;
        let (preset_name, _) = &presets[node.preset_index];

        // Build tree connector
        let indent = build_tree_prefix(state, node_id);

        // Node marker
        let marker = if node_id == 0 { "▶ " } else { "● " };

        // Trifecta check
        let is_vulnerable = node
            .effective_perms
            .as_ref()
            .map(|p| p.is_trifecta_vulnerable())
            .unwrap_or(false);

        let name_color = if is_selected {
            Color::Yellow
        } else if is_vulnerable {
            Color::Red
        } else {
            Color::White
        };

        let style = if is_selected {
            Style::default().fg(name_color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(name_color)
        };

        // Extract short spiffe name (last component)
        let short_name = node.spiffe_id.rsplit('/').next().unwrap_or(&node.spiffe_id);

        lines.push(Line::from(vec![
            Span::styled(indent, Style::default().fg(Color::DarkGray)),
            Span::styled(marker, style),
            Span::styled(format!("{} ", preset_name), style),
            Span::styled(short_name.to_string(), Style::default().fg(Color::Cyan)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "(empty forest)",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

/// Build the tree prefix string (e.g., "  ├─" or "  └─").
fn build_tree_prefix(state: &DelegationForestState, node_id: usize) -> String {
    let node = &state.nodes[node_id];
    if node.parent.is_none() {
        return String::new();
    }

    let mut parts: Vec<String> = Vec::new();
    let mut current = node_id;

    // Walk up to root, building prefix from bottom
    while let Some(parent_id) = state.nodes[current].parent {
        let siblings: Vec<usize> = state.nodes[parent_id]
            .children
            .iter()
            .filter(|&&c| !state.nodes[c].spiffe_id.is_empty())
            .copied()
            .collect();
        let is_last = siblings.last() == Some(&current);

        if current == node_id {
            // This is the node itself
            parts.push(if is_last {
                "└─".to_string()
            } else {
                "├─".to_string()
            });
        } else {
            // Ancestor continuation
            parts.push(if is_last {
                "  ".to_string()
            } else {
                "│ ".to_string()
            });
        }
        current = parent_id;
    }

    parts.reverse();
    parts.join("")
}

/// Draw the comparison sidebar (flat vs hierarchical model).
fn draw_comparison_sidebar(f: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Model Comparison ");

    // Vendor-neutral comparison (this is in nucleus, no Anthropic references)
    let lines = vec![
        Line::from(Span::styled(
            "╔═══════════════════╗",
            Style::default().fg(Color::Red),
        )),
        Line::from(Span::styled(
            "║  Flat Model       ║",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "║ ┌───────────────┐ ║",
            Style::default().fg(Color::Red),
        )),
        Line::from(Span::styled(
            "║ │ one sandbox   │ ║",
            Style::default().fg(Color::Red),
        )),
        Line::from(Span::styled(
            "║ │ same perms    │ ║",
            Style::default().fg(Color::Red),
        )),
        Line::from(Span::styled(
            "║ │ no hierarchy  │ ║",
            Style::default().fg(Color::Red),
        )),
        Line::from(Span::styled(
            "║ └───────────────┘ ║",
            Style::default().fg(Color::Red),
        )),
        Line::from(Span::styled(
            "╠═══════════════════╣",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "║ Hierarchical      ║",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "║ ┌─ orch ────────┐ ║",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "║ │ └─ codegen    │ ║",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "║ │    perms ≤ ∧  │ ║",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "║ │ └─ reviewer   │ ║",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "║ └───────────────┘ ║",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "╚═══════════════════╝",
            Style::default().fg(Color::Green),
        )),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

/// Draw node detail panel with capability heatmap and edge delta.
fn draw_detail_panel(f: &mut Frame, state: &DelegationForestState, area: Rect) {
    let node = &state.nodes[state.selected_node];
    let presets = &*PERMISSION_PRESETS;
    let (preset_name, _) = &presets[node.preset_index];

    let mut lines: Vec<Line> = Vec::new();

    // Mini heatmap of effective capabilities
    if let Some(ref eff) = node.effective_perms {
        let heatmap = capability_heatmap(&eff.capabilities);
        let trifecta = trifecta_badge(eff);
        let budget_str = format!("${:.2}", budget_for_preset(node.preset_index));

        lines.push(Line::from(vec![
            Span::styled("▶ ", Style::default().fg(Color::Yellow)),
            Span::styled(
                node.spiffe_id.rsplit('/').next().unwrap_or("?"),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}  ", preset_name),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(heatmap),
            Span::raw("  "),
            trifecta,
            Span::styled(
                format!("  {}", budget_str),
                Style::default().fg(Color::DarkGray),
            ),
        ]));

        // Edge delta (if not root)
        if let Some(parent_id) = node.parent {
            let deltas = state.edge_delta(parent_id, node.id);
            if !deltas.is_empty() {
                let delta_spans: Vec<Span> = std::iter::once(Span::styled(
                    "Edge ∧: ",
                    Style::default().fg(Color::DarkGray),
                ))
                .chain(deltas.iter().take(4).flat_map(|(name, from, to)| {
                    vec![Span::styled(
                        format!("{} {:?}→{:?}  ", name, from, to),
                        Style::default().fg(Color::Red),
                    )]
                }))
                .collect();
                lines.push(Line::from(delta_spans));
            } else {
                lines.push(Line::from(Span::styled(
                    "Edge ∧: no reductions (child profile ≤ parent ceiling)",
                    Style::default().fg(Color::Green),
                )));
            }
        }
    }

    // Escalation flash
    if let Some(ref esc) = state.escalation_status {
        let color = if esc.reductions.is_empty() {
            Color::Green
        } else {
            Color::Red
        };
        lines.push(Line::from(Span::styled(
            &esc.message,
            Style::default().fg(color),
        )));
    }

    let block = Block::default().borders(Borders::ALL).title(" Detail ");
    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(para, area);
}

/// Draw footer with key bindings.
fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[a]dd ", Style::default().fg(Color::Cyan)),
        Span::styled("[x]del ", Style::default().fg(Color::Red)),
        Span::styled("[p]cycle ", Style::default().fg(Color::Yellow)),
        Span::styled("[e]scalate! ", Style::default().fg(Color::Magenta)),
        Span::styled("[c]ompare ", Style::default().fg(Color::Green)),
        Span::styled("[hjkl]nav ", Style::default().fg(Color::White)),
        Span::styled("[Esc]back ", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(footer, area);
}

/// Build a 10-char heatmap of capability levels.
fn capability_heatmap(caps: &lattice_guard::CapabilityLattice) -> String {
    let levels = [
        caps.read_files,
        caps.write_files,
        caps.edit_files,
        caps.run_bash,
        caps.web_search,
        caps.web_fetch,
        caps.git_commit,
        caps.git_push,
        caps.create_pr,
        caps.manage_pods,
    ];
    levels
        .iter()
        .map(|l| match l {
            CapabilityLevel::Never => '⊥',
            CapabilityLevel::LowRisk => '◐',
            CapabilityLevel::Always => '⊤',
        })
        .collect()
}

/// Generate trifecta risk badge.
fn trifecta_badge(perms: &PermissionLattice) -> Span<'static> {
    let constraint = IncompatibilityConstraint::enforcing();
    let risk = constraint.trifecta_risk(&perms.capabilities);
    match risk {
        TrifectaRisk::None => Span::styled("[SAFE]", Style::default().fg(Color::Green)),
        TrifectaRisk::Low => Span::styled("[LOW]", Style::default().fg(Color::Green)),
        TrifectaRisk::Medium => Span::styled("[MED]", Style::default().fg(Color::Yellow)),
        TrifectaRisk::Complete => Span::styled(
            "[GATED]",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}

/// Simple budget estimate per preset.
fn budget_for_preset(preset_index: usize) -> f64 {
    let presets = &*PERMISSION_PRESETS;
    let (name, _) = &presets[preset_index];
    match *name {
        "PERMISSIVE" => 25.0,
        "ORCHESTRATOR" => 10.0,
        "CODEGEN" | "FIX_ISSUE" => 5.0,
        "PR_REVIEW" | "PR_APPROVE" | "RELEASE" => 3.0,
        "READ_ONLY" | "NETWORK_ONLY" => 1.0,
        "LOCAL_DEV" => 5.0,
        "RESTRICTIVE" => 0.5,
        _ => 2.0,
    }
}
