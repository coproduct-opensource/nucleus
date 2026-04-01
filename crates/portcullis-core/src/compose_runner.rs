//! Execution planning layer for multi-compartment compose workflows.
//!
//! This module takes a parsed [`ComposeWorkflow`] and produces an
//! [`ExecutionPlan`] — a topologically sorted sequence of agent
//! executions that respects flow dependencies.
//!
//! This is the **planning** layer only: it computes execution order
//! and parallel groups but does not spawn any processes.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::compose::ComposeWorkflow;

/// Errors that can occur when building an execution plan.
#[derive(Debug)]
pub enum PlanError {
    /// The workflow contains a circular dependency through flows.
    CyclicDependency {
        /// Agents involved in the cycle (not necessarily all of them).
        agents: Vec<String>,
    },
    /// The workflow has no agents to plan.
    Empty,
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CyclicDependency { agents } => {
                write!(f, "cyclic dependency among agents: {}", agents.join(" -> "))
            }
            Self::Empty => write!(f, "workflow defines no agents"),
        }
    }
}

impl std::error::Error for PlanError {}

/// A single agent execution step within the plan.
#[derive(Debug, Clone)]
pub struct AgentExecution {
    /// Unique agent name from the compose workflow.
    pub agent_name: String,
    /// Compartment this agent runs in.
    pub compartment: String,
    /// Optional policy profile to apply.
    pub profile: Option<String>,
    /// Environment variables for this agent.
    pub env: BTreeMap<String, String>,
    /// Names of agents that must complete before this one starts.
    /// Derived from flow definitions (an agent depends on all agents
    /// that flow data *into* it).
    pub depends_on: Vec<String>,
}

/// An ordered execution plan derived from a compose workflow.
///
/// The plan topologically sorts agents based on flow dependencies
/// so that every agent's upstream dependencies are satisfied before
/// it executes.
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// Agents in topological (dependency) order.
    steps: Vec<AgentExecution>,
}

impl ExecutionPlan {
    /// Build an execution plan from a validated compose workflow.
    ///
    /// Flow edges define dependencies: if there is a flow from agent A
    /// to agent B, then A must complete before B can start.
    ///
    /// Returns [`PlanError::CyclicDependency`] if the flow graph contains
    /// a cycle, or [`PlanError::Empty`] if no agents are defined.
    pub fn from_workflow(workflow: &ComposeWorkflow) -> Result<Self, PlanError> {
        if workflow.agents.is_empty() {
            return Err(PlanError::Empty);
        }

        // Build adjacency list and in-degree map from flows.
        // Flow "from -> to" means "from" must run before "to".
        let agent_names: Vec<&str> = workflow.agents.iter().map(|a| a.name.as_str()).collect();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut dependencies: HashMap<&str, Vec<&str>> = HashMap::new();

        for name in &agent_names {
            in_degree.insert(name, 0);
            dependents.insert(name, Vec::new());
            dependencies.insert(name, Vec::new());
        }

        for flow in &workflow.flows {
            let from = flow.from.as_str();
            let to = flow.to.as_str();
            // A flow from -> to means "to" depends on "from".
            *in_degree.get_mut(to).unwrap() += 1;
            dependents.get_mut(from).unwrap().push(to);
            dependencies.get_mut(to).unwrap().push(from);
        }

        // Kahn's algorithm for topological sort.
        let mut queue: VecDeque<&str> = VecDeque::new();
        for (&name, &deg) in &in_degree {
            if deg == 0 {
                queue.push_back(name);
            }
        }

        let mut sorted: Vec<&str> = Vec::with_capacity(agent_names.len());
        while let Some(name) = queue.pop_front() {
            sorted.push(name);
            for &dep in dependents.get(name).unwrap() {
                let deg = in_degree.get_mut(dep).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(dep);
                }
            }
        }

        if sorted.len() != agent_names.len() {
            // Cycle detected — collect the agents still with non-zero in-degree.
            let cycle_agents: Vec<String> = in_degree
                .iter()
                .filter(|&(_, &deg)| deg > 0)
                .map(|(&name, _)| name.to_string())
                .collect();
            return Err(PlanError::CyclicDependency {
                agents: cycle_agents,
            });
        }

        // Build AgentExecution steps in topological order.
        let agent_map: HashMap<&str, &crate::compose::AgentDef> = workflow
            .agents
            .iter()
            .map(|a| (a.name.as_str(), a))
            .collect();

        let steps: Vec<AgentExecution> = sorted
            .iter()
            .map(|&name| {
                let agent = agent_map[name];
                let deps: Vec<String> = dependencies
                    .get(name)
                    .map(|d| d.iter().map(|s| s.to_string()).collect())
                    .unwrap_or_default();
                AgentExecution {
                    agent_name: agent.name.clone(),
                    compartment: agent.compartment.clone(),
                    profile: agent.profile.clone(),
                    env: agent.env.clone(),
                    depends_on: deps,
                }
            })
            .collect();

        Ok(Self { steps })
    }

    /// Return agents in dependency order (agents with no dependencies first).
    pub fn execution_order(&self) -> &[AgentExecution] {
        &self.steps
    }

    /// Return groups of agents that can run concurrently.
    ///
    /// Each group contains agents whose dependencies are all satisfied
    /// by agents in previous groups. The first group contains agents
    /// with no dependencies.
    pub fn parallel_groups(&self) -> Vec<Vec<&AgentExecution>> {
        if self.steps.is_empty() {
            return Vec::new();
        }

        // Assign each agent a "depth" = max depth of dependencies + 1.
        let mut depth_map: HashMap<&str, usize> = HashMap::new();

        for step in &self.steps {
            let depth = if step.depends_on.is_empty() {
                0
            } else {
                step.depends_on
                    .iter()
                    .map(|dep| depth_map.get(dep.as_str()).copied().unwrap_or(0) + 1)
                    .max()
                    .unwrap_or(0)
            };
            depth_map.insert(&step.agent_name, depth);
        }

        let max_depth = depth_map.values().copied().max().unwrap_or(0);
        let mut groups: Vec<Vec<&AgentExecution>> = vec![Vec::new(); max_depth + 1];

        for step in &self.steps {
            let depth = depth_map[step.agent_name.as_str()];
            groups[depth].push(step);
        }

        groups
    }

    /// Return the number of agent execution steps.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Return whether the plan has no steps.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::compose::ComposeWorkflow;

    /// Helper: parse a TOML workflow and build the plan.
    fn plan_from_toml(toml: &str) -> Result<ExecutionPlan, PlanError> {
        let wf = ComposeWorkflow::parse(toml).expect("valid TOML");
        wf.validate(None).expect("valid workflow");
        ExecutionPlan::from_workflow(&wf)
    }

    #[test]
    fn linear_pipeline() {
        let toml = r#"
version = "1"

[[agents]]
name = "A"
compartment = "c1"

[[agents]]
name = "B"
compartment = "c2"

[[agents]]
name = "C"
compartment = "c3"

[[flows]]
from = "A"
to = "B"

[[flows]]
from = "B"
to = "C"
"#;
        let plan = plan_from_toml(toml).unwrap();
        let order: Vec<&str> = plan
            .execution_order()
            .iter()
            .map(|s| s.agent_name.as_str())
            .collect();
        assert_eq!(order, vec!["A", "B", "C"]);

        // Check dependencies.
        assert!(plan.execution_order()[0].depends_on.is_empty());
        assert_eq!(plan.execution_order()[1].depends_on, vec!["A"]);
        assert_eq!(plan.execution_order()[2].depends_on, vec!["B"]);

        // Parallel groups: each agent is its own group.
        let groups = plan.parallel_groups();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[0][0].agent_name, "A");
        assert_eq!(groups[1].len(), 1);
        assert_eq!(groups[1][0].agent_name, "B");
        assert_eq!(groups[2].len(), 1);
        assert_eq!(groups[2][0].agent_name, "C");
    }

    #[test]
    fn parallel_agents() {
        let toml = r#"
version = "1"

[[agents]]
name = "A"
compartment = "c1"

[[agents]]
name = "B"
compartment = "c2"

[[agents]]
name = "C"
compartment = "c3"
"#;
        // No flows — all agents can run in parallel.
        let plan = plan_from_toml(toml).unwrap();
        assert_eq!(plan.len(), 3);

        for step in plan.execution_order() {
            assert!(step.depends_on.is_empty());
        }

        let groups = plan.parallel_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 3);
    }

    #[test]
    fn diamond_dependency() {
        // A -> B, A -> C, B -> D, C -> D
        let toml = r#"
version = "1"

[[agents]]
name = "A"
compartment = "c1"

[[agents]]
name = "B"
compartment = "c2"

[[agents]]
name = "C"
compartment = "c3"

[[agents]]
name = "D"
compartment = "c4"

[[flows]]
from = "A"
to = "B"

[[flows]]
from = "A"
to = "C"

[[flows]]
from = "B"
to = "D"

[[flows]]
from = "C"
to = "D"
"#;
        let plan = plan_from_toml(toml).unwrap();
        let order: Vec<&str> = plan
            .execution_order()
            .iter()
            .map(|s| s.agent_name.as_str())
            .collect();

        // A must be first, D must be last, B and C in between.
        assert_eq!(order[0], "A");
        assert_eq!(order[3], "D");
        let middle: HashSet<&str> = order[1..3].iter().copied().collect();
        assert!(middle.contains("B"));
        assert!(middle.contains("C"));

        // D depends on both B and C.
        let d_deps: HashSet<&str> = plan.execution_order()[3]
            .depends_on
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert!(d_deps.contains("B"));
        assert!(d_deps.contains("C"));

        // Parallel groups: [A], [B, C], [D].
        let groups = plan.parallel_groups();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[0][0].agent_name, "A");
        assert_eq!(groups[1].len(), 2);
        let g1_names: HashSet<&str> = groups[1].iter().map(|s| s.agent_name.as_str()).collect();
        assert!(g1_names.contains("B"));
        assert!(g1_names.contains("C"));
        assert_eq!(groups[2].len(), 1);
        assert_eq!(groups[2][0].agent_name, "D");
    }

    #[test]
    fn cycle_detection() {
        let toml = r#"
version = "1"

[[agents]]
name = "A"
compartment = "c1"

[[agents]]
name = "B"
compartment = "c2"

[[agents]]
name = "C"
compartment = "c3"

[[flows]]
from = "A"
to = "B"

[[flows]]
from = "B"
to = "C"

[[flows]]
from = "C"
to = "A"
"#;
        let err = plan_from_toml(toml).unwrap_err();
        match err {
            PlanError::CyclicDependency { agents } => {
                assert!(!agents.is_empty());
                // All three agents should be in the cycle.
                let agent_set: HashSet<&str> = agents.iter().map(|s| s.as_str()).collect();
                assert!(agent_set.contains("A"));
                assert!(agent_set.contains("B"));
                assert!(agent_set.contains("C"));
            }
            other => panic!("expected CyclicDependency, got: {other}"),
        }
    }

    #[test]
    fn single_agent() {
        let toml = r#"
version = "1"

[[agents]]
name = "solo"
compartment = "sandbox"
profile = "codegen"

[agents.env]
FOO = "bar"
"#;
        let plan = plan_from_toml(toml).unwrap();
        assert_eq!(plan.len(), 1);
        assert!(!plan.is_empty());

        let step = &plan.execution_order()[0];
        assert_eq!(step.agent_name, "solo");
        assert_eq!(step.compartment, "sandbox");
        assert_eq!(step.profile.as_deref(), Some("codegen"));
        assert_eq!(step.env.get("FOO").unwrap(), "bar");
        assert!(step.depends_on.is_empty());

        let groups = plan.parallel_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 1);
    }

    #[test]
    fn empty_workflow() {
        let toml = r#"
version = "1"
agents = []
"#;
        let wf = ComposeWorkflow::parse(toml).unwrap();
        let err = ExecutionPlan::from_workflow(&wf).unwrap_err();
        assert!(matches!(err, PlanError::Empty));
    }
}
