//! The oracle: the SPIFFE ID grammar and this taxonomy's rules, written from
//! the specification and `docs/spiffe-taxonomy.md`, not read from any parser.
//!
//! Every implementation the walk drives is compared against these functions.
//! They are deliberately the dumbest correct reading of the text: one pass,
//! no shared helpers with the code under test.

/// A parsed ID: the trust domain and the path segments, in order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id {
    pub td: String,
    pub segs: Vec<String>,
}

impl Id {
    pub fn uri(&self) -> String {
        format!("spiffe://{}/{}", self.td, self.segs.join("/"))
    }
}

/// SPIFFE: "The maximum length of a SPIFFE ID is 2048 bytes."
pub const MAX_ID: usize = 2048;
/// SPIFFE: "Trust domain names ... a maximum length of 255 bytes."
pub const MAX_TD: usize = 255;

fn td_ok(td: &str) -> bool {
    // SPIFFE allows [a-z0-9._-]; this taxonomy drops `_` (a trust domain is a
    // DNS name here). Lowercase only: SPIFFE says implementations MUST NOT
    // treat a mixed-case trust domain as valid, never fold it.
    !td.is_empty()
        && td.len() <= MAX_TD
        && td
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

fn seg_ok(seg: &str) -> bool {
    // SPIFFE: segments are non-empty, [A-Za-z0-9._-], and "Paths MUST NOT
    // include . or .. segments". No percent-encoding: `%` is not in the set.
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn split(s: &str) -> Option<(&str, Vec<&str>)> {
    if s.len() > MAX_ID {
        return None;
    }
    let rest = s.strip_prefix("spiffe://")?;
    let slash = rest.find('/')?;
    let (td, path) = (&rest[..slash], &rest[slash + 1..]);
    Some((td, path.split('/').collect()))
}

/// The fields of an ID string, read without judging it: what a parser that
/// accepted `s` unchanged must have parsed.
pub fn fields(s: &str) -> Option<Id> {
    let (td, segs) = split(s)?;
    Some(Id {
        td: td.to_string(),
        segs: segs.iter().map(|g| g.to_string()).collect(),
    })
}

/// The core grammar: a workload SPIFFE ID in this taxonomy (at least one path
/// segment; a bare trust domain is not a workload).
pub fn core(s: &str) -> Option<Id> {
    let (td, segs) = split(s)?;
    (td_ok(td) && segs.iter().all(|g| seg_ok(g))).then(|| Id {
        td: td.to_string(),
        segs: segs.iter().map(|g| g.to_string()).collect(),
    })
}

/// A nucleus principal: the core grammar in the shape
/// `ns/<namespace>/sa/<account>[/<segment>...]`.
pub fn principal(s: &str) -> Option<Id> {
    core(s).filter(|id| id.segs.len() >= 4 && id.segs[0] == "ns" && id.segs[2] == "sa")
}

fn canonical_uuid(seg: &str) -> bool {
    // 8-4-4-4-12 lowercase hex, the form the node and lineage mint.
    let b = seg.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

fn sha256_seg(seg: &str) -> bool {
    seg.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

/// A lineage call ID: the core grammar, plus the reserved `sha256:<hex>`
/// segment form, plus the `call` rule — the segment `call` (exactly, any other
/// casing refused) is always followed by a canonical uuid.
pub fn lineage(s: &str) -> Option<Id> {
    let (td, segs) = split(s)?;
    if !td_ok(td) || !segs.iter().all(|g| seg_ok(g) || sha256_seg(g)) {
        return None;
    }
    for (i, g) in segs.iter().enumerate() {
        if g.eq_ignore_ascii_case("call") && *g != "call" {
            return None;
        }
        if *g == "call" && !segs.get(i + 1).is_some_and(|u| canonical_uuid(u)) {
            return None;
        }
    }
    Some(Id {
        td: td.to_string(),
        segs: segs.iter().map(|g| g.to_string()).collect(),
    })
}

/// The node's operations, as the walk enumerates them.
pub const OPS: [crate::auth::Operation; 9] = {
    use crate::auth::Operation::*;
    [
        CreatePod,
        ListPods,
        GetPod,
        CancelPod,
        StreamLogs,
        GetReceipt,
        SnapshotPod,
        Lockdown,
        PodManagement,
    ]
};

/// What the node's policy grants an ID, decided from the rules as
/// `docs/spiffe-taxonomy.md` states them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    Nothing,
    NodeWide,
    Ci(String),
    Pod(uuid::Uuid),
    Tenant(String),
}

/// The bitmask of [`OPS`] the policy grants, and the scope `caller_scope`
/// resolves (no caller token). `node_td` with operator `node_td/ns/system/sa/cli`,
/// tenants `tenants`.
pub fn authority(s: &str, node_td: &str, tenants: &[&str]) -> (u16, Reach) {
    use crate::auth::Operation::*;
    let mask = |ops: &[crate::auth::Operation]| {
        OPS.iter()
            .enumerate()
            .filter(|(_, o)| ops.contains(o))
            .fold(0u16, |m, (i, _)| m | (1 << i))
    };
    let Some(id) = principal(s) else {
        return (0, Reach::Nothing);
    };
    let pod_mgmt = [
        CreatePod,
        ListPods,
        GetPod,
        CancelPod,
        StreamLogs,
        GetReceipt,
        PodManagement,
    ];
    if tenants.contains(&id.td.as_str()) && id.td != node_td {
        return (mask(&pod_mgmt), Reach::Tenant(id.td));
    }
    if id.td != node_td {
        return (0, Reach::Nothing);
    }
    let seg = |i: usize| id.segs[i].as_str();
    if id.segs.len() == 4 && seg(1) == "system" && seg(3) == "cli" {
        return (mask(&OPS), Reach::NodeWide);
    }
    match seg(1) {
        "default" | "workstream-kg" => (mask(&OPS), Reach::NodeWide),
        "github" => {
            let mut ci = pod_mgmt.to_vec();
            ci.push(SnapshotPod);
            (mask(&ci), Reach::Ci(s.to_string()))
        }
        "pods" => {
            let reach = match (id.segs.len(), canonical_uuid(seg(3))) {
                (4, true) => Reach::Pod(seg(3).parse().expect("canonical uuid")),
                _ => Reach::Nothing,
            };
            (mask(&pod_mgmt), reach)
        }
        _ => (0, Reach::Nothing),
    }
}
