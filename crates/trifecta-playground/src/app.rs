//! Application state and logic.

use lattice_guard::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations,
    PermissionLattice, TrifectaRisk,
    escalation::{SpiffeTraceChain, SpiffeTraceLink},
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
            chain: vec![
                ChainLink {
                    spiffe_id: "spiffe://nucleus.local/human/alice".to_string(),
                    preset_index: 0, // Permissive
                },
            ],
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
}

impl SelectedCapability {
    pub fn all() -> &'static [SelectedCapability] {
        use SelectedCapability::*;
        &[ReadFiles, WriteFiles, EditFiles, RunBash, WebSearch, WebFetch, GitCommit, GitPush, CreatePr]
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

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
