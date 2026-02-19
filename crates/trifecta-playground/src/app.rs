//! Application state and logic.

use lattice_guard::{
    escalation::{SpiffeTraceChain, SpiffeTraceLink},
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations, PermissionLattice,
    TrifectaRisk,
};

use crate::demo::{ATTACK_SCENARIOS, PRESETS};

/// The current screen being displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Main trifecta detection screen
    Trifecta,
    /// SPIFFE trace chain visualization
    TraceChain,
    /// Attack simulator
    Attacks,
    /// Capability matrix showing all presets
    Matrix,
    /// Hasse diagram of permission lattice
    Hasse,
    /// Meet playground for computing meets
    Meet,
    /// Chain builder for SPIFFE delegation chains
    ChainBuilder,
    /// Help screen
    Help,
    /// Delegation forest visualization
    DelegationForest,
}

/// Side selection for meet playground.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetSide {
    Left,
    Right,
}

/// State for the meet playground screen.
#[derive(Debug, Clone)]
pub struct MeetPlayground {
    /// Left permission set (index into PERMISSION_PRESETS or None for custom)
    pub left: Option<usize>,
    /// Right permission set (index into PERMISSION_PRESETS or None for custom)
    pub right: Option<usize>,
    /// Which side is currently being selected
    pub selecting: MeetSide,
    /// Computed meet result
    pub result: Option<PermissionLattice>,
}

impl Default for MeetPlayground {
    fn default() -> Self {
        Self {
            left: Some(0),  // Start with first preset
            right: Some(1), // And second preset
            selecting: MeetSide::Left,
            result: None,
        }
    }
}

impl MeetPlayground {
    /// Compute the meet of the two selected permission sets.
    pub fn compute_meet(&mut self) {
        let presets = &*crate::demo::PERMISSION_PRESETS;
        let left = self.left.map(|i| &presets[i].1);
        let right = self.right.map(|i| &presets[i].1);

        if let (Some(l), Some(r)) = (left, right) {
            self.result = Some(l.meet(r));
        }
    }

    /// Cycle to the next preset for the current side.
    pub fn next_preset(&mut self) {
        let current = match self.selecting {
            MeetSide::Left => &mut self.left,
            MeetSide::Right => &mut self.right,
        };
        let len = crate::demo::PERMISSION_PRESETS.len();
        *current = Some((current.unwrap_or(0) + 1) % len);
        self.result = None;
    }

    /// Cycle to the previous preset for the current side.
    pub fn prev_preset(&mut self) {
        let current = match self.selecting {
            MeetSide::Left => &mut self.left,
            MeetSide::Right => &mut self.right,
        };
        let len = crate::demo::PERMISSION_PRESETS.len();
        *current = Some((current.unwrap_or(0) + len - 1) % len);
        self.result = None;
    }

    /// Toggle which side is being selected.
    pub fn toggle_side(&mut self) {
        self.selecting = match self.selecting {
            MeetSide::Left => MeetSide::Right,
            MeetSide::Right => MeetSide::Left,
        };
    }
}

/// A link in the chain builder.
#[derive(Debug, Clone)]
pub struct ChainLink {
    /// SPIFFE ID for this link
    pub spiffe_id: String,
    /// Preset index for permission profile
    pub preset_index: usize,
}

/// State for the chain builder screen.
#[derive(Debug, Clone)]
pub struct ChainBuilderState {
    /// The chain of links
    pub chain: Vec<ChainLink>,
    /// Currently selected link index
    pub selected_link: usize,
    /// Whether we're editing the current link (for future inline editing)
    #[allow(dead_code)]
    pub editing: bool,
    /// Computed ceiling (meet of all permissions in chain)
    pub ceiling: Option<PermissionLattice>,
}

impl Default for ChainBuilderState {
    fn default() -> Self {
        Self {
            chain: vec![ChainLink {
                spiffe_id: "spiffe://nucleus.local/human/alice".to_string(),
                preset_index: 0, // Permissive
            }],
            selected_link: 0,
            editing: false,
            ceiling: None,
        }
    }
}

impl ChainBuilderState {
    /// Add a new link to the chain.
    pub fn add_link(&mut self) {
        let num = self.chain.len();
        self.chain.push(ChainLink {
            spiffe_id: format!("spiffe://nucleus.local/agent/coder-{:03}", num),
            preset_index: 2, // Codegen by default
        });
        self.selected_link = self.chain.len() - 1;
        self.ceiling = None;
    }

    /// Remove the last link (if more than one exists).
    pub fn remove_last(&mut self) {
        if self.chain.len() > 1 {
            self.chain.pop();
            if self.selected_link >= self.chain.len() {
                self.selected_link = self.chain.len() - 1;
            }
            self.ceiling = None;
        }
    }

    /// Move selection up.
    pub fn prev_link(&mut self) {
        if self.selected_link > 0 {
            self.selected_link -= 1;
        }
    }

    /// Move selection down.
    pub fn next_link(&mut self) {
        if self.selected_link < self.chain.len() - 1 {
            self.selected_link += 1;
        }
    }

    /// Cycle the preset for the selected link.
    pub fn cycle_preset(&mut self) {
        if let Some(link) = self.chain.get_mut(self.selected_link) {
            let len = crate::demo::PERMISSION_PRESETS.len();
            link.preset_index = (link.preset_index + 1) % len;
            self.ceiling = None;
        }
    }

    /// Compute the ceiling (meet of all permissions in chain).
    pub fn compute_ceiling(&mut self) {
        if self.chain.is_empty() {
            self.ceiling = None;
            return;
        }

        let presets = &*crate::demo::PERMISSION_PRESETS;
        let mut result = presets[self.chain[0].preset_index].1.clone();
        for link in self.chain.iter().skip(1) {
            result = result.meet(&presets[link.preset_index].1);
        }
        self.ceiling = Some(result);
    }
}

/// State for the Hasse diagram screen.
#[derive(Debug, Clone, Default)]
pub struct HasseState {
    /// Currently selected node index
    pub selected_node: usize,
    /// Whether we're in meet selection mode
    pub meet_mode: bool,
    /// First node selected for meet (when in meet mode)
    pub meet_first: Option<usize>,
}

/// Which capability is currently selected for editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedCapability {
    ReadFiles,
    WriteFiles,
    EditFiles,
    RunBash,
    WebSearch,
    WebFetch,
    GitCommit,
    GitPush,
    CreatePr,
    ManagePods,
}

impl SelectedCapability {
    pub fn all() -> &'static [SelectedCapability] {
        use SelectedCapability::*;
        &[
            ReadFiles, WriteFiles, EditFiles, RunBash, WebSearch, WebFetch, GitCommit, GitPush,
            CreatePr, ManagePods,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ReadFiles => "read_files",
            Self::WriteFiles => "write_files",
            Self::EditFiles => "edit_files",
            Self::RunBash => "run_bash",
            Self::WebSearch => "web_search",
            Self::WebFetch => "web_fetch",
            Self::GitCommit => "git_commit",
            Self::GitPush => "git_push",
            Self::CreatePr => "create_pr",
            Self::ManagePods => "manage_pods",
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Self::ReadFiles => 0,
            Self::WriteFiles => 1,
            Self::EditFiles => 2,
            Self::RunBash => 3,
            Self::WebSearch => 4,
            Self::WebFetch => 5,
            Self::GitCommit => 6,
            Self::GitPush => 7,
            Self::CreatePr => 8,
            Self::ManagePods => 9,
        }
    }

    pub fn from_index(idx: usize) -> Self {
        Self::all()[idx % Self::all().len()]
    }

    /// Which trifecta component does this capability belong to?
    pub fn trifecta_component(&self) -> Option<TrifectaComponent> {
        match self {
            Self::ReadFiles => Some(TrifectaComponent::PrivateData),
            Self::WebSearch | Self::WebFetch => Some(TrifectaComponent::UntrustedContent),
            Self::GitPush | Self::CreatePr | Self::RunBash => Some(TrifectaComponent::Exfiltration),
            _ => None,
        }
    }
}

/// The three components of the lethal trifecta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrifectaComponent {
    PrivateData,
    UntrustedContent,
    Exfiltration,
}

/// Application state.
pub struct App {
    /// Current screen
    pub screen: Screen,
    /// Current capability lattice
    pub capabilities: CapabilityLattice,
    /// Currently selected capability
    pub selected_capability: SelectedCapability,
    /// SPIFFE trace chain for demo
    pub trace_chain: SpiffeTraceChain,
    /// Chain verification status message
    pub chain_status: Option<String>,
    /// Currently selected attack
    pub selected_attack: usize,
    /// Last attack result
    pub attack_result: Option<AttackResult>,
    /// Current preset index (for display)
    pub current_preset: Option<usize>,
    /// State for the meet playground
    pub meet_playground: MeetPlayground,
    /// State for the chain builder
    pub chain_builder: ChainBuilderState,
    /// State for the Hasse diagram
    pub hasse_state: HasseState,
    /// Currently selected row in the matrix view
    pub matrix_selected_row: usize,
    /// State for the delegation forest
    pub delegation_forest: DelegationForestState,
}

/// Result of running an attack scenario.
pub struct AttackResult {
    pub blocked: bool,
    pub defense: String,
}

impl HasseState {
    /// Get the number of nodes in the Hasse diagram.
    pub fn node_count() -> usize {
        crate::demo::PERMISSION_PRESETS.len()
    }

    /// Navigate to the next node.
    pub fn next_node(&mut self) {
        self.selected_node = (self.selected_node + 1) % Self::node_count();
    }

    /// Navigate to the previous node.
    pub fn prev_node(&mut self) {
        let count = Self::node_count();
        self.selected_node = (self.selected_node + count - 1) % count;
    }

    /// Toggle meet mode.
    pub fn toggle_meet_mode(&mut self) {
        if self.meet_mode {
            // Exit meet mode
            self.meet_mode = false;
            self.meet_first = None;
        } else {
            // Enter meet mode, select current node as first
            self.meet_mode = true;
            self.meet_first = Some(self.selected_node);
        }
    }

    /// Select second node for meet and compute result.
    pub fn select_meet_second(&mut self) -> Option<PermissionLattice> {
        if self.meet_mode {
            if let Some(first) = self.meet_first {
                let presets = &*crate::demo::PERMISSION_PRESETS;
                let second = self.selected_node;
                let left = &presets[first].1;
                let right = &presets[second].1;
                let result = left.meet(right);
                self.meet_mode = false;
                self.meet_first = None;
                return Some(result);
            }
        }
        None
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Trifecta,
            capabilities: CapabilityLattice::default(),
            selected_capability: SelectedCapability::ReadFiles,
            trace_chain: SpiffeTraceChain::new_root(
                "spiffe://nucleus.local/human/alice",
                PermissionLattice::permissive(),
                12345,
            ),
            chain_status: None,
            selected_attack: 0,
            attack_result: None,
            current_preset: None,
            meet_playground: MeetPlayground::default(),
            chain_builder: ChainBuilderState::default(),
            hasse_state: HasseState::default(),
            matrix_selected_row: 0,
            delegation_forest: DelegationForestState::default(),
        }
    }

    /// Get the current trifecta risk level.
    pub fn trifecta_risk(&self) -> TrifectaRisk {
        let constraint = IncompatibilityConstraint::enforcing();
        constraint.trifecta_risk(&self.capabilities)
    }

    /// Check which trifecta components are active.
    pub fn active_components(&self) -> (bool, bool, bool) {
        let has_private = self.capabilities.read_files >= CapabilityLevel::LowRisk;
        let has_untrusted = self.capabilities.web_fetch >= CapabilityLevel::LowRisk
            || self.capabilities.web_search >= CapabilityLevel::LowRisk;
        let has_exfil = self.capabilities.git_push >= CapabilityLevel::LowRisk
            || self.capabilities.create_pr >= CapabilityLevel::LowRisk
            || self.capabilities.run_bash >= CapabilityLevel::LowRisk;
        (has_private, has_untrusted, has_exfil)
    }

    /// Get current obligations.
    pub fn obligations(&self) -> Obligations {
        let constraint = IncompatibilityConstraint::enforcing();
        constraint.obligations_for(&self.capabilities)
    }

    /// Get the capability level for the selected capability.
    pub fn get_capability(&self, cap: SelectedCapability) -> CapabilityLevel {
        match cap {
            SelectedCapability::ReadFiles => self.capabilities.read_files,
            SelectedCapability::WriteFiles => self.capabilities.write_files,
            SelectedCapability::EditFiles => self.capabilities.edit_files,
            SelectedCapability::RunBash => self.capabilities.run_bash,
            SelectedCapability::WebSearch => self.capabilities.web_search,
            SelectedCapability::WebFetch => self.capabilities.web_fetch,
            SelectedCapability::GitCommit => self.capabilities.git_commit,
            SelectedCapability::GitPush => self.capabilities.git_push,
            SelectedCapability::CreatePr => self.capabilities.create_pr,
            SelectedCapability::ManagePods => self.capabilities.manage_pods,
        }
    }

    /// Set the capability level for the selected capability.
    pub fn set_capability(&mut self, cap: SelectedCapability, level: CapabilityLevel) {
        match cap {
            SelectedCapability::ReadFiles => self.capabilities.read_files = level,
            SelectedCapability::WriteFiles => self.capabilities.write_files = level,
            SelectedCapability::EditFiles => self.capabilities.edit_files = level,
            SelectedCapability::RunBash => self.capabilities.run_bash = level,
            SelectedCapability::WebSearch => self.capabilities.web_search = level,
            SelectedCapability::WebFetch => self.capabilities.web_fetch = level,
            SelectedCapability::GitCommit => self.capabilities.git_commit = level,
            SelectedCapability::GitPush => self.capabilities.git_push = level,
            SelectedCapability::CreatePr => self.capabilities.create_pr = level,
            SelectedCapability::ManagePods => self.capabilities.manage_pods = level,
        }
        self.current_preset = None;
    }

    /// Navigate to previous capability.
    pub fn prev_capability(&mut self) {
        let idx = self.selected_capability.index();
        let new_idx = if idx == 0 {
            SelectedCapability::all().len() - 1
        } else {
            idx - 1
        };
        self.selected_capability = SelectedCapability::from_index(new_idx);
    }

    /// Navigate to next capability.
    pub fn next_capability(&mut self) {
        let idx = self.selected_capability.index();
        self.selected_capability = SelectedCapability::from_index(idx + 1);
    }

    /// Decrease capability level.
    pub fn decrease_capability(&mut self) {
        let current = self.get_capability(self.selected_capability);
        let new_level = match current {
            CapabilityLevel::Always => CapabilityLevel::LowRisk,
            CapabilityLevel::LowRisk => CapabilityLevel::Never,
            CapabilityLevel::Never => CapabilityLevel::Never,
        };
        self.set_capability(self.selected_capability, new_level);
    }

    /// Increase capability level.
    pub fn increase_capability(&mut self) {
        let current = self.get_capability(self.selected_capability);
        let new_level = match current {
            CapabilityLevel::Never => CapabilityLevel::LowRisk,
            CapabilityLevel::LowRisk => CapabilityLevel::Always,
            CapabilityLevel::Always => CapabilityLevel::Always,
        };
        self.set_capability(self.selected_capability, new_level);
    }

    /// Toggle capability between Never and Always.
    pub fn toggle_capability(&mut self) {
        let current = self.get_capability(self.selected_capability);
        let new_level = match current {
            CapabilityLevel::Never => CapabilityLevel::Always,
            _ => CapabilityLevel::Never,
        };
        self.set_capability(self.selected_capability, new_level);
    }

    /// Load a preset configuration.
    pub fn load_preset(&mut self, idx: usize) {
        if idx < PRESETS.len() {
            self.capabilities = PRESETS[idx].1.clone();
            self.current_preset = Some(idx);
        }
    }

    /// Navigate to previous attack.
    pub fn prev_attack(&mut self) {
        if self.selected_attack > 0 {
            self.selected_attack -= 1;
        } else {
            self.selected_attack = ATTACK_SCENARIOS.len() - 1;
        }
        self.attack_result = None;
    }

    /// Navigate to next attack.
    pub fn next_attack(&mut self) {
        self.selected_attack = (self.selected_attack + 1) % ATTACK_SCENARIOS.len();
        self.attack_result = None;
    }

    /// Run the currently selected attack.
    pub fn run_attack(&mut self) {
        let scenario = &ATTACK_SCENARIOS[self.selected_attack];
        self.attack_result = Some(scenario.run());
    }

    /// Extend the trace chain with a new agent.
    pub fn extend_chain(&mut self) {
        let agent_num = self.trace_chain.links.len();
        let spiffe_id = format!("spiffe://nucleus.local/agent/coder-{:03}", agent_num);

        // Each delegation reduces permissions (ceiling theorem)
        let perms = if agent_num == 1 {
            PermissionLattice::codegen()
        } else {
            PermissionLattice::read_only()
        };

        let link = SpiffeTraceLink::new(spiffe_id, perms, 12345 + agent_num as u64);
        self.trace_chain.extend(link);
        self.chain_status = Some("Chain extended".to_string());
    }

    /// Verify the trace chain.
    pub fn verify_chain(&mut self) {
        if self.trace_chain.verify() {
            self.chain_status = Some("Chain verified successfully".to_string());
        } else {
            self.chain_status = Some("Chain verification FAILED".to_string());
        }
    }

    /// Reset the trace chain.
    pub fn reset_chain(&mut self) {
        self.trace_chain = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );
        self.chain_status = Some("Chain reset to root".to_string());
    }
}

/// A node in the delegation forest (arena-based tree).
pub struct ForestNode {
    pub id: usize,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub spiffe_id: String,
    pub preset_index: usize,
    pub effective_perms: Option<PermissionLattice>,
    pub depth: usize,
}

/// Result of attempting escalation.
pub struct EscalationResult {
    pub message: String,
    pub reductions: Vec<(String, CapabilityLevel, CapabilityLevel)>,
}

/// State for the delegation forest screen.
pub struct DelegationForestState {
    pub nodes: Vec<ForestNode>,
    pub selected_node: usize,
    pub escalation_status: Option<EscalationResult>,
    pub show_comparison: bool,
}

impl Default for DelegationForestState {
    fn default() -> Self {
        let presets = &*crate::demo::PERMISSION_PRESETS;
        // Find ORCHESTRATOR index, fallback to 0
        let orch_idx = presets
            .iter()
            .position(|(n, _)| *n == "ORCHESTRATOR")
            .unwrap_or(0);
        let root_perms = presets[orch_idx].1.clone();
        let root = ForestNode {
            id: 0,
            parent: None,
            children: vec![],
            spiffe_id: "spiffe://nucleus.local/orchestrator/root".to_string(),
            preset_index: orch_idx,
            effective_perms: Some(root_perms),
            depth: 0,
        };
        Self {
            nodes: vec![root],
            selected_node: 0,
            escalation_status: None,
            show_comparison: false,
        }
    }
}

impl DelegationForestState {
    /// Add a child node under the selected node with the given preset.
    pub fn add_child(&mut self, preset_index: usize) {
        let presets = &*crate::demo::PERMISSION_PRESETS;
        let parent_id = self.selected_node;
        let parent_depth = self.nodes[parent_id].depth;
        let child_num = self.nodes.len();
        let (preset_name, _) = &presets[preset_index];
        let spiffe_id = format!(
            "spiffe://nucleus.local/agent/{}-{:03}",
            preset_name.to_lowercase(),
            child_num
        );
        let new_id = self.nodes.len();
        let child = ForestNode {
            id: new_id,
            parent: Some(parent_id),
            children: vec![],
            spiffe_id,
            preset_index,
            effective_perms: None,
            depth: parent_depth + 1,
        };
        self.nodes.push(child);
        self.nodes[parent_id].children.push(new_id);
        self.recompute_effective(new_id);
        self.selected_node = new_id;
        self.escalation_status = None;
    }

    /// Add a child with a cycling default preset.
    pub fn add_child_default(&mut self) {
        let presets = &*crate::demo::PERMISSION_PRESETS;
        // Cycle through useful presets: CODEGEN, PR_REVIEW, READ_ONLY, FIX_ISSUE
        let useful = [2, 3, 7, 5]; // CODEGEN, PR_REVIEW, READ_ONLY, FIX_ISSUE
        let child_count = self.nodes[self.selected_node].children.len();
        let idx = useful[child_count % useful.len()];
        let idx = idx.min(presets.len() - 1);
        self.add_child(idx);
    }

    /// Attempt escalation: try creating a child with PERMISSIVE profile.
    pub fn attempt_escalation(&mut self) {
        let presets = &*crate::demo::PERMISSION_PRESETS;
        let parent_id = self.selected_node;
        let parent_effective = match &self.nodes[parent_id].effective_perms {
            Some(p) => p.clone(),
            None => return,
        };
        // PERMISSIVE is index 0
        let requested = &presets[0].1;
        let clamped = parent_effective.meet(requested);

        let mut reductions = Vec::new();
        let cap_names = [
            "read_files",
            "write_files",
            "edit_files",
            "run_bash",
            "web_search",
            "web_fetch",
            "git_commit",
            "git_push",
            "create_pr",
            "manage_pods",
        ];
        let req_levels = [
            requested.capabilities.read_files,
            requested.capabilities.write_files,
            requested.capabilities.edit_files,
            requested.capabilities.run_bash,
            requested.capabilities.web_search,
            requested.capabilities.web_fetch,
            requested.capabilities.git_commit,
            requested.capabilities.git_push,
            requested.capabilities.create_pr,
            requested.capabilities.manage_pods,
        ];
        let got_levels = [
            clamped.capabilities.read_files,
            clamped.capabilities.write_files,
            clamped.capabilities.edit_files,
            clamped.capabilities.run_bash,
            clamped.capabilities.web_search,
            clamped.capabilities.web_fetch,
            clamped.capabilities.git_commit,
            clamped.capabilities.git_push,
            clamped.capabilities.create_pr,
            clamped.capabilities.manage_pods,
        ];
        for i in 0..cap_names.len() {
            if got_levels[i] < req_levels[i] {
                reductions.push((cap_names[i].to_string(), req_levels[i], got_levels[i]));
            }
        }

        let message = if reductions.is_empty() {
            "No reductions — escalation succeeded (parent is already permissive)".to_string()
        } else {
            format!(
                "Escalation clamped: {} capabilities reduced by monotonic meet",
                reductions.len()
            )
        };
        self.escalation_status = Some(EscalationResult {
            message,
            reductions,
        });
    }

    /// Remove the selected node and all its descendants.
    pub fn remove_selected(&mut self) {
        if self.selected_node == 0 {
            return; // Can't remove root
        }
        let node_id = self.selected_node;
        let parent_id = self.nodes[node_id].parent.unwrap_or(0);

        // Collect all descendant IDs
        let mut to_remove = vec![node_id];
        let mut i = 0;
        while i < to_remove.len() {
            let id = to_remove[i];
            to_remove.extend(self.nodes[id].children.clone());
            i += 1;
        }

        // Remove from parent's children list
        self.nodes[parent_id].children.retain(|c| *c != node_id);

        // Mark removed nodes (set parent to a sentinel, clear children)
        // We can't actually remove from the arena without reindexing,
        // so we mark them as orphaned with empty spiffe_id
        for &id in &to_remove {
            self.nodes[id].children.clear();
            self.nodes[id].parent = None;
            self.nodes[id].spiffe_id = String::new();
            self.nodes[id].effective_perms = None;
        }

        self.selected_node = parent_id;
        self.escalation_status = None;
    }

    /// Navigate to parent.
    pub fn go_to_parent(&mut self) {
        if let Some(parent) = self.nodes[self.selected_node].parent {
            self.selected_node = parent;
            self.escalation_status = None;
        }
    }

    /// Navigate to first child.
    pub fn go_to_first_child(&mut self) {
        let children: Vec<usize> = self.nodes[self.selected_node]
            .children
            .iter()
            .filter(|&&c| !self.nodes[c].spiffe_id.is_empty())
            .copied()
            .collect();
        if let Some(&first) = children.first() {
            self.selected_node = first;
            self.escalation_status = None;
        }
    }

    /// Navigate to next sibling.
    pub fn go_to_next_sibling(&mut self) {
        if let Some(parent_id) = self.nodes[self.selected_node].parent {
            let siblings: Vec<usize> = self.nodes[parent_id]
                .children
                .iter()
                .filter(|&&c| !self.nodes[c].spiffe_id.is_empty())
                .copied()
                .collect();
            if let Some(pos) = siblings.iter().position(|&s| s == self.selected_node) {
                if pos + 1 < siblings.len() {
                    self.selected_node = siblings[pos + 1];
                    self.escalation_status = None;
                }
            }
        }
    }

    /// Navigate to previous sibling.
    pub fn go_to_prev_sibling(&mut self) {
        if let Some(parent_id) = self.nodes[self.selected_node].parent {
            let siblings: Vec<usize> = self.nodes[parent_id]
                .children
                .iter()
                .filter(|&&c| !self.nodes[c].spiffe_id.is_empty())
                .copied()
                .collect();
            if let Some(pos) = siblings.iter().position(|&s| s == self.selected_node) {
                if pos > 0 {
                    self.selected_node = siblings[pos - 1];
                    self.escalation_status = None;
                }
            }
        }
    }

    /// Cycle the profile on the selected node.
    pub fn cycle_preset(&mut self) {
        let len = crate::demo::PERMISSION_PRESETS.len();
        self.nodes[self.selected_node].preset_index =
            (self.nodes[self.selected_node].preset_index + 1) % len;
        self.recompute_subtree(self.selected_node);
        self.escalation_status = None;
    }

    /// Toggle comparison sidebar.
    pub fn toggle_comparison(&mut self) {
        self.show_comparison = !self.show_comparison;
    }

    /// Recompute effective permissions for a node (walk from root).
    pub fn recompute_effective(&mut self, node_id: usize) {
        let presets = &*crate::demo::PERMISSION_PRESETS;
        // Build path from root to node
        let mut path = vec![node_id];
        let mut current = node_id;
        while let Some(parent) = self.nodes[current].parent {
            path.push(parent);
            current = parent;
        }
        path.reverse();

        // Compute cumulative meet along path
        let mut effective = presets[self.nodes[path[0]].preset_index].1.clone();
        for &id in path.iter().skip(1) {
            let node_perms = &presets[self.nodes[id].preset_index].1;
            effective = effective.meet(node_perms);
        }
        self.nodes[node_id].effective_perms = Some(effective);
    }

    /// Recompute effective permissions for a node and all its descendants.
    fn recompute_subtree(&mut self, node_id: usize) {
        self.recompute_effective(node_id);
        let children: Vec<usize> = self.nodes[node_id].children.clone();
        for child_id in children {
            if !self.nodes[child_id].spiffe_id.is_empty() {
                self.recompute_subtree(child_id);
            }
        }
    }

    /// Compare parent and child effective permissions, return reductions.
    pub fn edge_delta(
        &self,
        parent_id: usize,
        child_id: usize,
    ) -> Vec<(String, CapabilityLevel, CapabilityLevel)> {
        let parent_eff = match &self.nodes[parent_id].effective_perms {
            Some(p) => p,
            None => return vec![],
        };
        let child_eff = match &self.nodes[child_id].effective_perms {
            Some(p) => p,
            None => return vec![],
        };
        let cap_names = [
            "read_files",
            "write_files",
            "edit_files",
            "run_bash",
            "web_search",
            "web_fetch",
            "git_commit",
            "git_push",
            "create_pr",
            "manage_pods",
        ];
        let parent_levels = [
            parent_eff.capabilities.read_files,
            parent_eff.capabilities.write_files,
            parent_eff.capabilities.edit_files,
            parent_eff.capabilities.run_bash,
            parent_eff.capabilities.web_search,
            parent_eff.capabilities.web_fetch,
            parent_eff.capabilities.git_commit,
            parent_eff.capabilities.git_push,
            parent_eff.capabilities.create_pr,
            parent_eff.capabilities.manage_pods,
        ];
        let child_levels = [
            child_eff.capabilities.read_files,
            child_eff.capabilities.write_files,
            child_eff.capabilities.edit_files,
            child_eff.capabilities.run_bash,
            child_eff.capabilities.web_search,
            child_eff.capabilities.web_fetch,
            child_eff.capabilities.git_commit,
            child_eff.capabilities.git_push,
            child_eff.capabilities.create_pr,
            child_eff.capabilities.manage_pods,
        ];
        let mut reductions = Vec::new();
        for i in 0..cap_names.len() {
            if child_levels[i] < parent_levels[i] {
                reductions.push((cap_names[i].to_string(), parent_levels[i], child_levels[i]));
            }
        }
        reductions
    }

    /// Count active (non-deleted) nodes.
    pub fn active_node_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| !n.spiffe_id.is_empty())
            .count()
    }

    /// Get max depth of active nodes.
    pub fn max_depth(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| !n.spiffe_id.is_empty())
            .map(|n| n.depth)
            .max()
            .unwrap_or(0)
    }

    /// Get ordered list of visible nodes for rendering (DFS order).
    pub fn visible_nodes(&self) -> Vec<usize> {
        let mut result = Vec::new();
        self.collect_visible(0, &mut result);
        result
    }

    fn collect_visible(&self, node_id: usize, result: &mut Vec<usize>) {
        if self.nodes[node_id].spiffe_id.is_empty() {
            return;
        }
        result.push(node_id);
        for &child_id in &self.nodes[node_id].children {
            self.collect_visible(child_id, result);
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
