//! Test support: read a fenced Markdown inventory table out of a doc.
//!
//! Two closed enums in this crate are pinned to a documented table each
//! ([`crate::EgressChannel`] to `mediated-set.md`, [`crate::HostListener`] to
//! the host-listener table in the same doc). One parser serves both (ADR 0007 F-4), so the two
//! parity gates cannot read their tables differently.
//!
//! The table is bounded by explicit start/end markers, and a cell is located by
//! its HEADER NAME, never by position — reordering or inserting a human column
//! cannot silently desync a gate. Machine cells are backticked; the backticks
//! are stripped.

use std::collections::BTreeMap;

/// Read `docs/architecture/<name>` from the repository root.
pub(crate) fn read_doc(name: &str) -> String {
    let path = format!(
        "{}/../../docs/architecture/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path} must be readable from the crate manifest dir: {e}"))
}

/// One parsed table: each row maps a header name to its (unticked) cell.
pub(crate) struct DocTable {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl DocTable {
    /// Parse the table between `<!-- {marker}-START -->` and
    /// `<!-- {marker}-END -->`. Panics (the test's failure) when a marker is
    /// missing, out of order, or the block holds no header plus row.
    pub(crate) fn parse(doc: &str, marker: &str) -> Self {
        let start_tag = format!("<!-- {marker}-START -->");
        let end_tag = format!("<!-- {marker}-END -->");
        let start = doc
            .find(&start_tag)
            .unwrap_or_else(|| panic!("{start_tag} marker present"));
        let end = doc
            .find(&end_tag)
            .unwrap_or_else(|| panic!("{end_tag} marker present"));
        assert!(start < end, "{marker} markers out of order");

        let mut rows: Vec<Vec<String>> = doc[start..end]
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('|'))
            // drop the separator row (|---|---|)
            .filter(|l| !l.trim_start_matches('|').trim_start().starts_with('-'))
            .map(|l| {
                l.trim_matches('|')
                    .split('|')
                    .map(|c| c.trim().trim_matches('`').trim().to_string())
                    .collect()
            })
            .collect();
        assert!(rows.len() >= 2, "{marker} table must have a header + rows");
        let header = rows.remove(0);
        Self { header, rows }
    }

    /// The column named `name` (case-insensitive) for every row.
    pub(crate) fn column(&self, name: &str) -> Vec<&str> {
        let col = self
            .header
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("table header must have a '{name}' column"));
        self.rows
            .iter()
            .map(|r| {
                r.get(col)
                    .map(String::as_str)
                    .unwrap_or_else(|| panic!("row {r:?} has no '{name}' cell"))
            })
            .collect()
    }

    /// `key column -> value column`, refusing an empty or duplicated key.
    pub(crate) fn keyed(&self, key: &str, value: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (k, v) in self.column(key).into_iter().zip(self.column(value)) {
            assert!(!k.is_empty(), "a row has an empty '{key}' cell");
            assert!(
                out.insert(k.to_string(), v.to_string()).is_none(),
                "duplicate documented key: {k}"
            );
        }
        out
    }
}
