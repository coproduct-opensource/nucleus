//! Thin wrapper around an embedded egglog 2.0 `EGraph` running the trust-atlas
//! program (`src/atlas.egg`).
//!
//! PROVENANCE IS NON-NEGOTIABLE: every base-fact insertion takes a citation
//! string (file:line or URL). The wrapper keeps the authoritative provenance
//! map on the Rust side (for printing) and mirrors it into the in-engine
//! `provenance` relation.

use anyhow::{Context, Result};
use egglog::{CommandOutput, EGraph};
use std::collections::BTreeMap;

use crate::model::Maturity;

pub struct Atlas {
    eg: EGraph,
    /// fact key -> citation (file:line or URL). Authoritative for reports.
    pub provenance: BTreeMap<String, String>,
    /// equivalence name -> fragment condition (side table; the union is still
    /// performed — conditions are reported, not used to skip transport).
    pub fragments: BTreeMap<String, String>,
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

impl Atlas {
    pub fn new() -> Result<Self> {
        let mut eg = EGraph::default();
        eg.parse_and_run_program(Some("atlas.egg".to_string()), include_str!("atlas.egg"))
            .map_err(|e| anyhow::anyhow!("loading atlas.egg: {e}"))?;
        Ok(Self {
            eg,
            provenance: BTreeMap::new(),
            fragments: BTreeMap::new(),
        })
    }

    fn run(&mut self, program: &str) -> Result<Vec<CommandOutput>> {
        self.eg
            .parse_and_run_program(None, program)
            .map_err(|e| anyhow::anyhow!("egglog: {e}\nprogram: {program}"))
    }

    fn record(&mut self, key: String, citation: &str) -> Result<()> {
        let prog = format!("(provenance \"{}\" \"{}\")", esc(&key), esc(citation));
        self.run(&prog)?;
        self.provenance.insert(key, citation.to_string());
        Ok(())
    }

    /// Assert a node maturity fact with a mandatory citation.
    pub fn set_maturity(&mut self, artifact: &str, m: Maturity, citation: &str) -> Result<()> {
        let prog = format!("(set (maturity (Art \"{}\")) {})", esc(artifact), m.rank());
        self.run(&prog)?;
        self.record(format!("maturity:{artifact}"), citation)
    }

    /// Assert a per-edge maturity fact with a mandatory citation.
    pub fn set_edge(&mut self, from: &str, to: &str, m: Maturity, citation: &str) -> Result<()> {
        let prog = format!(
            "(set (edge-maturity (Art \"{}\") (Art \"{}\")) {})",
            esc(from),
            esc(to),
            m.rank()
        );
        self.run(&prog)?;
        self.record(format!("edge:{from} -> {to}"), citation)
    }

    /// Assert a CI gate fact (required on main or advisory).
    pub fn add_gate(&mut self, name: &str, required: bool, citation: &str) -> Result<()> {
        let prog = format!("(gate \"{}\" {})", esc(name), if required { 1 } else { 0 });
        self.run(&prog)?;
        self.record(format!("gate:{name}"), citation)
    }

    /// Equivalence transport: ALWAYS (union lhs rhs); fragment conditions go
    /// to a side table (in-engine `equiv-fragment` + Rust map), never skip.
    pub fn add_equivalence(
        &mut self,
        name: &str,
        lhs: &str,
        rhs: &str,
        rank: Maturity,
        fragment_condition: &str,
        citation: &str,
    ) -> Result<()> {
        let mut prog = format!(
            "(union (Art \"{l}\") (Art \"{r}\"))\n\
             (set (maturity (Art \"{l}\")) {rank})",
            l = esc(lhs),
            r = esc(rhs),
            rank = rank.rank()
        );
        if !fragment_condition.is_empty() {
            prog.push_str(&format!(
                "\n(equiv-fragment \"{}\" \"{}\")",
                esc(name),
                esc(fragment_condition)
            ));
            self.fragments
                .insert(name.to_string(), fragment_condition.to_string());
        }
        self.run(&prog)?;
        self.record(format!("equiv:{name}"), citation)
    }

    /// Saturate the rule set (path propagation + unenforced-gate finding).
    pub fn saturate(&mut self) -> Result<()> {
        // The rule set is monotone and the fact base finite; 64 iterations is
        // far past fixpoint for chains of this size.
        self.run("(run 64)")?;
        Ok(())
    }

    fn extract_i64(&mut self, expr: &str) -> Option<i64> {
        let outs = self.run(&format!("(extract {expr})")).ok()?;
        for out in outs {
            if let CommandOutput::ExtractBest(termdag, _cost, term) = out {
                return termdag.to_string(term).parse().ok();
            }
        }
        None
    }

    /// Current maturity of an artifact (post-union congruence applies: a fact
    /// asserted on one side of an equivalence is queryable from the other).
    pub fn maturity(&mut self, artifact: &str) -> Option<Maturity> {
        let rank = self.extract_i64(&format!("(maturity (Art \"{}\"))", esc(artifact)))?;
        Maturity::from_rank(rank)
    }

    /// Best end-to-end maturity from `from` to `to` (min along a path).
    pub fn path_maturity(&mut self, from: &str, to: &str) -> Option<Maturity> {
        let rank = self.extract_i64(&format!(
            "(path-maturity (Art \"{}\") (Art \"{}\"))",
            esc(from),
            esc(to)
        ))?;
        Maturity::from_rank(rank)
    }

    /// Did the unenforced-gate rule derive this gate?
    pub fn is_unenforced(&mut self, gate: &str) -> bool {
        self.run(&format!("(check (unenforced-gate \"{}\"))", esc(gate)))
            .is_ok()
    }

    /// Citation for a fact key; reports must refuse to print uncited facts.
    pub fn citation(&self, key: &str) -> Result<&str> {
        self.provenance
            .get(key)
            .map(String::as_str)
            .with_context(|| format!("fact '{key}' has no provenance — refusing to report it"))
    }
}
