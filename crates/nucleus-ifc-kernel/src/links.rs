//! The link table (ADR 0017): which pod may open connections to which, and the
//! live connections each link carries.
//!
//! This is the list half of the split [`crate::extracted::link`] describes. Each
//! method is one transition of `LinkTable.step` in
//! `crates/portcullis-core/lean/LinkTable.lean`, and decides through the
//! extracted predicates, never a restatement of them. The tests are named after
//! the Lean theorems they hold this code to; the property test drives random
//! operation sequences and checks `Inv` after every step.
//!
//! Not wired to a route (ADR 0017 L3): nothing in the node calls this yet.

use crate::extracted::link::{
    Link, link_matches, may_cancel, may_deliver, may_link, may_unlink, names,
};
use std::collections::BTreeMap;

/// A pod id: its UUID as a `u128`.
pub type PodId = u128;

/// Who is asking (the node API's `CallerScope`, reduced to what decides a link).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    NodeWide,
    /// A federated tenant: a SPIFFE trust domain (ADR 0001).
    Tenant(String),
    /// One pod, acting on itself.
    Pod(PodId),
}

/// A live connection, relayed by the host along one link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conn {
    pub id: u64,
    pub link: Link,
}

/// What a receipt says happened (`LinkTable.Effect`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Link(Link),
    /// An unlink, naming the connections it severed.
    Unlink {
        link: Link,
        severed: Vec<u64>,
    },
    Connect(Conn),
    /// One request over a connection, with the host's decision applied.
    Request(Conn),
    /// A connection ended.
    Close(Conn),
    Cancel(PodId),
    /// A link dropped because a pod exited without being asked to.
    Drop(Link),
}

/// Whether the node did it. Two cases, so no `bool` stands in for a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Refused,
}

/// An unsigned receipt; signing is L4's (`nucleus-receipt`, `Projection::Link`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub effect: Effect,
    pub outcome: Outcome,
}

impl Receipt {
    fn done(effect: Effect) -> Receipt {
        Receipt {
            effect,
            outcome: Outcome::Done,
        }
    }
    fn refused(effect: Effect) -> Receipt {
        Receipt {
            effect,
            outcome: Outcome::Refused,
        }
    }
}

/// The table, with the live pods and their trust domains it decides against.
#[derive(Clone, Debug)]
pub struct LinkTable {
    pods: BTreeMap<PodId, String>,
    links: Vec<Link>,
    conns: Vec<Conn>,
}

impl LinkTable {
    /// An empty table over no pods.
    #[must_use]
    pub fn empty() -> LinkTable {
        LinkTable {
            pods: BTreeMap::new(),
            links: Vec::new(),
            conns: Vec::new(),
        }
    }

    /// A pod came up, in `trust_domain`.
    pub fn pod_started(&mut self, pod: PodId, trust_domain: String) {
        self.pods.insert(pod, trust_domain);
    }

    #[must_use]
    pub fn links(&self) -> &[Link] {
        &self.links
    }

    #[must_use]
    pub fn conns(&self) -> &[Conn] {
        &self.conns
    }

    fn live(&self, pod: PodId) -> bool {
        self.pods.contains_key(&pod)
    }

    /// `LinkTable.manages`.
    fn manages(&self, scope: &Scope, pod: PodId) -> bool {
        match scope {
            Scope::NodeWide => self.live(pod),
            Scope::Tenant(td) => self.pods.get(&pod) == Some(td),
            Scope::Pod(me) => self.live(pod) && pod == *me,
        }
    }

    fn present(&self, link: Link) -> bool {
        self.links
            .iter()
            .any(|l| link_matches(*l, link.src, link.dst, link.port))
    }

    /// `step (.link s l)`.
    pub fn link(&mut self, scope: &Scope, link: Link) -> Receipt {
        let same_td = match (self.pods.get(&link.src), self.pods.get(&link.dst)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        };
        if may_link(
            self.manages(scope, link.src),
            self.manages(scope, link.dst),
            same_td,
            link.src,
            link.dst,
            self.present(link),
        ) {
            self.links.push(link);
            Receipt::done(Effect::Link(link))
        } else {
            Receipt::refused(Effect::Link(link))
        }
    }

    /// `step (.unlink s l)`: severs every connection the link carries, and names
    /// them, before the receipt.
    pub fn unlink(&mut self, scope: &Scope, link: Link) -> Receipt {
        if may_unlink(self.present(link), self.manages(scope, link.src)) {
            let carried = |c: &Conn| link_matches(c.link, link.src, link.dst, link.port);
            let severed = self
                .conns
                .iter()
                .filter(|c| carried(c))
                .map(|c| c.id)
                .collect();
            self.conns.retain(|c| !carried(c));
            self.links
                .retain(|l| !link_matches(*l, link.src, link.dst, link.port));
            Receipt::done(Effect::Unlink { link, severed })
        } else {
            Receipt::refused(Effect::Unlink {
                link,
                severed: Vec::new(),
            })
        }
    }

    /// `step (.connect i l)`: the relay admits a connection only along a link.
    pub fn connect(&mut self, id: u64, link: Link) -> Receipt {
        let conn = Conn { id, link };
        if self.present(link) {
            self.conns.push(conn);
            Receipt::done(Effect::Connect(conn))
        } else {
            Receipt::refused(Effect::Connect(conn))
        }
    }

    /// `step (.request c v)`: one request is delivered only if the connection is
    /// live and the host's pod policy admitted it. `host_admits` is that
    /// decision, taken before this call by the host, never by a guest.
    pub fn request(&self, conn: Conn, host_admits: bool) -> Receipt {
        if may_deliver(self.conns.contains(&conn), host_admits) {
            Receipt::done(Effect::Request(conn))
        } else {
            Receipt::refused(Effect::Request(conn))
        }
    }

    /// `step (.close c)`: the connection ended (closed by the workload, or its
    /// single request answered). It leaves every other connection; without it the
    /// table only grows.
    pub fn close(&mut self, conn: Conn) -> Receipt {
        if self.conns.contains(&conn) {
            self.conns.retain(|c| *c != conn);
            Receipt::done(Effect::Close(conn))
        } else {
            Receipt::refused(Effect::Close(conn))
        }
    }

    /// `step (.cancel s p)`: refused while a link names the pod.
    pub fn cancel(&mut self, scope: &Scope, pod: PodId) -> Receipt {
        let linked = self.links.iter().any(|l| names(*l, pod));
        if may_cancel(self.manages(scope, pod), linked) {
            self.pods.remove(&pod);
            Receipt::done(Effect::Cancel(pod))
        } else {
            Receipt::refused(Effect::Cancel(pod))
        }
    }

    /// `step (.exit p)`: the pod exited without being asked. Its links and their
    /// connections go, with one receipt per dropped link.
    pub fn exit(&mut self, pod: PodId) -> Vec<Receipt> {
        let dropped: Vec<Receipt> = self
            .links
            .iter()
            .filter(|l| names(**l, pod))
            .map(|l| Receipt::done(Effect::Drop(*l)))
            .collect();
        self.pods.remove(&pod);
        self.links.retain(|l| !names(*l, pod));
        self.conns.retain(|c| !names(c.link, pod));
        dropped
    }

    /// `LinkTable.Inv`: connections ride links; links join live pods of one
    /// trust domain.
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        let rides = self.conns.iter().all(|c| self.links.contains(&c.link));
        let joins = self.links.iter().all(|l| {
            matches!((self.pods.get(&l.src), self.pods.get(&l.dst)), (Some(a), Some(b)) if a == b)
        });
        rides && joins
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const P1: PodId = 1;
    const P2: PodId = 2;
    const P3: PodId = 3;

    fn td(s: &str) -> String {
        s.to_owned()
    }

    /// `LinkTable.demo`: pods 1 and 2 in one trust domain, pod 3 in another.
    fn demo() -> LinkTable {
        let mut t = LinkTable::empty();
        t.pod_started(P1, td("a.example"));
        t.pod_started(P2, td("a.example"));
        t.pod_started(P3, td("b.example"));
        t
    }

    fn l12() -> Link {
        Link {
            src: P1,
            dst: P2,
            port: 80,
        }
    }

    /// `no_cross_tenant_link`, and the worked cases.
    #[test]
    fn no_cross_tenant_link() {
        let mut t = demo();
        let across = Link {
            src: P1,
            dst: P3,
            port: 80,
        };
        assert_eq!(t.link(&Scope::NodeWide, across).outcome, Outcome::Refused);
        assert_eq!(
            t.link(&Scope::Tenant(td("a.example")), across).outcome,
            Outcome::Refused
        );
        assert_eq!(
            t.link(&Scope::Tenant(td("a.example")), l12()).outcome,
            Outcome::Done
        );
        assert_eq!(
            t.link(&Scope::Tenant(td("b.example")), l12()).outcome,
            Outcome::Refused,
            "a tenant cannot link another tenant's pods"
        );
    }

    /// `connect_only_along_links`.
    #[test]
    fn connect_only_along_links() {
        let mut t = demo();
        assert_eq!(t.connect(5, l12()).outcome, Outcome::Refused);
        t.link(&Scope::NodeWide, l12());
        assert_eq!(t.connect(5, l12()).outcome, Outcome::Done);
        assert!(t.invariant_holds());
    }

    /// `unlink_severs`: the receipt names the severed connection, and no
    /// connection on the link survives.
    #[test]
    fn unlink_severs() {
        let mut t = demo();
        t.link(&Scope::NodeWide, l12());
        t.connect(5, l12());
        let r = t.unlink(&Scope::NodeWide, l12());
        assert_eq!(
            r,
            Receipt::done(Effect::Unlink {
                link: l12(),
                severed: vec![5]
            })
        );
        assert!(t.conns().is_empty());
    }

    /// `request_is_a_decision`: delivery needs a live connection AND the host.
    #[test]
    fn request_is_a_decision() {
        let mut t = demo();
        t.link(&Scope::NodeWide, l12());
        t.connect(5, l12());
        let c = Conn { id: 5, link: l12() };
        assert_eq!(t.request(c, true).outcome, Outcome::Done);
        assert_eq!(t.request(c, false).outcome, Outcome::Refused);
        let gone = Conn { id: 6, link: l12() };
        assert_eq!(t.request(gone, true).outcome, Outcome::Refused);
    }

    /// `cancel_refuses_linked` and `exit_drops_links`.
    #[test]
    fn cancel_refuses_linked_and_exit_drops_links() {
        let mut t = demo();
        t.link(&Scope::NodeWide, l12());
        t.connect(5, l12());
        assert_eq!(t.cancel(&Scope::NodeWide, P2).outcome, Outcome::Refused);
        assert!(t.live(P2), "a refused cancel changes nothing");
        let receipts = t.exit(P2);
        assert_eq!(receipts, vec![Receipt::done(Effect::Drop(l12()))]);
        assert!(t.links().is_empty() && t.conns().is_empty());
        assert!(t.invariant_holds());
    }

    /// `close_removes` and `connect_request_close_bounded`: a connection that
    /// carries its one request and is closed leaves no trace, so many requests
    /// over one link leave the table no larger.
    #[test]
    fn close_removes() {
        let mut t = demo();
        t.link(&Scope::NodeWide, l12());
        for id in 0..100 {
            t.connect(id, l12());
            let c = Conn { id, link: l12() };
            assert_eq!(t.request(c, true).outcome, Outcome::Done);
            assert_eq!(t.close(c), Receipt::done(Effect::Close(c)));
            assert!(!t.conns().contains(&c));
        }
        assert!(t.conns().is_empty());
        assert_eq!(
            t.close(Conn { id: 7, link: l12() }).outcome,
            Outcome::Refused,
            "closing what is not open is refused"
        );
    }

    fn op() -> impl Strategy<Value = (u8, u128, u128, u32, u64)> {
        (0u8..7, 1u128..5, 1u128..5, 79u32..82, 0u64..4)
    }

    proptest! {
        /// `step_inv`: from the empty table, every sequence of operations keeps
        /// the invariant. Pod 4 never starts, so links to it must be refused.
        #[test]
        fn step_inv(ops in proptest::collection::vec(op(), 0..40)) {
            let mut t = demo();
            for (kind, a, b, port, id) in ops {
                let link = Link { src: a, dst: b, port };
                let scope = if a % 2 == 0 { Scope::NodeWide } else { Scope::Tenant(td("a.example")) };
                match kind {
                    0 => { t.link(&scope, link); }
                    1 => { t.unlink(&scope, link); }
                    2 => { t.connect(id, link); }
                    3 => { t.cancel(&scope, a); }
                    4 => { t.exit(a); }
                    5 => { t.close(Conn { id, link }); }
                    _ => { t.request(Conn { id, link }, true); }
                }
                prop_assert!(t.invariant_holds());
            }
        }
    }
}
