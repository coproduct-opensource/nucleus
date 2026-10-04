//! Round-trip, refusal, raise-only and single-use tests.

use proptest::prelude::*;

use crate::codec::wire_tables::{
    AUTHORITY_ALL, CONF_ALL, DERIVATION_ALL, GuestTag, HostTag, INTEG_ALL, authority_wire,
    conf_wire, deny_wire, derivation_wire, integ_wire, op_wire,
};
use crate::host::{DecisionLedger, LedgerError, Redemption, SeqError, SeqGate};
use crate::*;

// ── builders ────────────────────────────────────────────────────────────────

const EPOCH: u64 = 0x5eed;

fn label(
    c: ConfLevel,
    i: IntegLevel,
    p: u8,
    observed_at: u64,
    ttl_secs: u64,
    a: AuthorityLevel,
    d: DerivationClass,
) -> IFCLabel {
    IFCLabel {
        confidentiality: c,
        integrity: i,
        provenance: ProvenanceSet::from_bits(p),
        freshness: Freshness {
            observed_at,
            ttl_secs,
        },
        authority: a,
        derivation: d,
    }
}

fn decide(seq: u64, subject: &str) -> GuestFrame {
    GuestFrame::Decide {
        seq: Seq::new(seq),
        op: Operation::WebFetch,
        subject: Subject::new(subject).expect("short subject"),
        args_digest: ArgsDigest::new([0xab; ArgsDigest::LEN]),
    }
}

/// One of every frame, both directions.
fn every_guest_frame() -> Vec<GuestFrame> {
    vec![
        decide(0, "https://example.test/path"),
        GuestFrame::Observe {
            seq: Seq::new(1),
            label_raise: LabelRaise::new(IFCLabel::web_content(1_700_000_000)),
        },
        GuestFrame::Redeem {
            seq: Seq::new(u64::MAX),
            approval_id: ApprovalId::mint(EPOCH, 7),
        },
    ]
}

fn every_host_frame() -> Vec<HostFrame> {
    let mut v = vec![
        HostFrame::Verdict {
            seq: Seq::new(0),
            verdict: Verdict::Allowed {
                decision_id: DecisionId::mint(EPOCH, 42),
            },
        },
        HostFrame::Verdict {
            seq: Seq::new(2),
            verdict: Verdict::ApprovalRequired {
                approval_id: ApprovalId::mint(EPOCH, u64::MAX),
            },
        },
        HostFrame::Observed { seq: Seq::new(1) },
    ];
    for reason in DenyReason::ALL {
        v.push(HostFrame::Verdict {
            seq: Seq::new(3),
            verdict: Verdict::Denied { reason },
        });
    }
    v
}

fn enc_g(f: &GuestFrame) -> Vec<u8> {
    f.encode().expect("encodable")
}

fn enc_h(f: &HostFrame) -> Vec<u8> {
    f.encode().expect("encodable")
}

/// A guest frame's body with the prefix stripped, for hand-editing.
fn body_of(frame: &[u8]) -> Vec<u8> {
    frame[LEN_PREFIX..].to_vec()
}

/// Re-frame an edited body with a correct prefix.
fn reframe(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

// ── round trip ──────────────────────────────────────────────────────────────

#[test]
fn every_frame_round_trips() {
    for f in every_guest_frame() {
        let bytes = enc_g(&f);
        let back = GuestFrame::decode(&bytes).expect("decodes");
        assert_eq!(back, f);
        // Canonical: the decoded value encodes to the same bytes.
        assert_eq!(enc_g(&back), bytes);
        // And the I/O layer's two-step path agrees with the one-shot path.
        let len = body_len(bytes[..LEN_PREFIX].try_into().unwrap()).unwrap();
        assert_eq!(len, bytes.len() - LEN_PREFIX);
        assert_eq!(GuestFrame::decode_body(&bytes[LEN_PREFIX..]).unwrap(), f);
    }
    for f in every_host_frame() {
        let bytes = enc_h(&f);
        let back = HostFrame::decode(&bytes).expect("decodes");
        assert_eq!(back, f);
        assert_eq!(enc_h(&back), bytes);
        assert_eq!(HostFrame::decode_body(&bytes[LEN_PREFIX..]).unwrap(), f);
    }
}

/// Every value of every enum on the wire round-trips, and no two share a byte.
/// This is what catches a variant missing from a decoder's search list.
#[test]
fn every_enum_value_round_trips() {
    fn check<T: Copy + PartialEq + std::fmt::Debug>(all: &[T], wire: fn(T) -> u8) {
        let mut seen = std::collections::BTreeSet::new();
        for v in all {
            assert!(seen.insert(wire(*v)), "{v:?} shares a wire byte");
        }
    }
    check(&Operation::ALL, op_wire);
    check(&CONF_ALL, conf_wire);
    check(&INTEG_ALL, integ_wire);
    check(&AUTHORITY_ALL, authority_wire);
    check(&DERIVATION_ALL, derivation_wire);
    check(&DenyReason::ALL, deny_wire);

    // Every operation, through a real frame.
    for op in Operation::ALL {
        let f = GuestFrame::Decide {
            seq: Seq::FIRST,
            op,
            subject: Subject::new("x").unwrap(),
            args_digest: ArgsDigest::new([0; ArgsDigest::LEN]),
        };
        assert_eq!(GuestFrame::decode(&enc_g(&f)).unwrap(), f);
    }
    // Every label component, through a real frame.
    for c in CONF_ALL {
        for i in INTEG_ALL {
            for a in AUTHORITY_ALL {
                for d in DERIVATION_ALL {
                    let f = GuestFrame::Observe {
                        seq: Seq::FIRST,
                        label_raise: LabelRaise::new(label(c, i, 0x3f, 9, 0, a, d)),
                    };
                    assert_eq!(GuestFrame::decode(&enc_g(&f)).unwrap(), f);
                }
            }
        }
    }
}

#[test]
fn guest_and_host_tags_are_disjoint() {
    for g in GuestTag::ALL {
        for h in HostTag::ALL {
            assert_ne!(g.wire(), h.wire(), "{g:?} and {h:?} share a tag");
        }
    }
}

#[test]
fn a_reflected_frame_is_an_unknown_tag() {
    for f in every_host_frame() {
        let bytes = enc_h(&f);
        assert!(matches!(
            GuestFrame::decode(&bytes),
            Err(FrameError::UnknownTag { .. })
        ));
    }
    for f in every_guest_frame() {
        let bytes = enc_g(&f);
        assert!(matches!(
            HostFrame::decode(&bytes),
            Err(FrameError::UnknownTag { .. })
        ));
    }
}

#[test]
fn max_decide_is_max_body() {
    let subject = "s".repeat(MAX_SUBJECT_LEN);
    let f = decide(0, &subject);
    let bytes = enc_g(&f);
    assert_eq!(bytes.len(), LEN_PREFIX + MAX_BODY_LEN);
    assert_eq!(GuestFrame::decode(&bytes).unwrap(), f);
    // Every other frame is smaller.
    for g in every_guest_frame() {
        assert!(enc_g(&g).len() < bytes.len());
    }
    for h in every_host_frame() {
        assert!(enc_h(&h).len() < bytes.len());
    }
}

#[test]
fn max_subject_encodes() {
    assert!(Subject::new("s".repeat(MAX_SUBJECT_LEN)).is_ok());
    assert_eq!(
        Subject::new("s".repeat(MAX_SUBJECT_LEN + 1)),
        Err(SubjectError::TooLong {
            len: MAX_SUBJECT_LEN + 1
        })
    );
    assert!(u16::try_from(MAX_SUBJECT_LEN).is_ok());
}

// ── refusals, each named ───────────────────────────────────────────────────

#[test]
fn oversize_prefix_is_refused_before_the_body() {
    // Only the four prefix bytes exist: the refusal must come from them alone.
    let declared = u32::try_from(MAX_BODY_LEN + 1).unwrap();
    let only_prefix = declared.to_be_bytes();
    assert_eq!(
        GuestFrame::decode(&only_prefix),
        Err(FrameError::LengthPrefixTooLarge { declared })
    );
    assert_eq!(
        body_len(u32::MAX.to_be_bytes()),
        Err(FrameError::LengthPrefixTooLarge { declared: u32::MAX })
    );
    assert_eq!(
        body_len(u32::try_from(MAX_BODY_LEN).unwrap().to_be_bytes()),
        Ok(MAX_BODY_LEN)
    );
    let too_long = vec![0u8; MAX_BODY_LEN + 1];
    assert_eq!(
        GuestFrame::decode_body(&too_long),
        Err(FrameError::BodyTooLong {
            len: MAX_BODY_LEN + 1
        })
    );
}

#[test]
fn trailing_bytes_are_refused_in_both_places() {
    let bytes = enc_g(&decide(0, "a"));

    // After the frame.
    let mut stream = bytes.clone();
    stream.push(0);
    assert_eq!(
        GuestFrame::decode(&stream),
        Err(FrameError::TrailingBytes {
            region: Region::Stream,
            extra: 1
        })
    );

    // Inside the declared length, after the variant.
    let mut body = body_of(&bytes);
    body.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        GuestFrame::decode(&reframe(&body)),
        Err(FrameError::TrailingBytes {
            region: Region::Body,
            extra: 3
        })
    );
}

#[test]
fn every_truncation_is_refused() {
    for f in every_guest_frame() {
        let bytes = enc_g(&f);
        for cut in 0..bytes.len() {
            assert!(
                matches!(
                    GuestFrame::decode(&bytes[..cut]),
                    Err(FrameError::Truncated { .. })
                ),
                "cut at {cut} of {f:?}"
            );
            // A body cut short but correctly reframed is truncated too (or,
            // when the cut removes the tag/version, still refused).
            let body = &bytes[LEN_PREFIX..cut.max(LEN_PREFIX)];
            assert!(GuestFrame::decode_body(body).is_err());
        }
    }
    for f in every_host_frame() {
        let bytes = enc_h(&f);
        for cut in 0..bytes.len() {
            assert!(matches!(
                HostFrame::decode(&bytes[..cut]),
                Err(FrameError::Truncated { .. })
            ));
        }
    }
}

#[test]
fn unknown_version_tag_and_discriminants_are_named() {
    let bytes = enc_g(&decide(0, "a"));
    let body = body_of(&bytes);

    let mut v = body.clone();
    v[0] = VERSION + 1;
    assert_eq!(
        GuestFrame::decode(&reframe(&v)),
        Err(FrameError::UnsupportedVersion { got: VERSION + 1 })
    );

    let mut t = body.clone();
    t[1] = 0x7f;
    assert_eq!(
        GuestFrame::decode(&reframe(&t)),
        Err(FrameError::UnknownTag { got: 0x7f })
    );

    // Operation byte follows version, tag and the 8-byte seq.
    let mut o = body.clone();
    o[10] = 13;
    assert_eq!(
        GuestFrame::decode(&reframe(&o)),
        Err(FrameError::UnknownDiscriminant {
            field: Field::Operation,
            got: 13
        })
    );

    // Denied reason.
    let denied = enc_h(&HostFrame::Verdict {
        seq: Seq::FIRST,
        verdict: Verdict::Denied {
            reason: DenyReason::NotGranted,
        },
    });
    let mut d = body_of(&denied);
    d[10] = 0xee;
    assert_eq!(
        HostFrame::decode(&reframe(&d)),
        Err(FrameError::UnknownDiscriminant {
            field: Field::DenyReason,
            got: 0xee
        })
    );
}

#[test]
fn label_fields_are_checked() {
    let obs = enc_g(&GuestFrame::Observe {
        seq: Seq::FIRST,
        label_raise: LabelRaise::new(IFCLabel::bottom()),
    });
    let body = body_of(&obs);
    // label starts after version, tag, seq: offset 10.
    let cases: [(usize, u8, FrameError); 5] = [
        (
            10,
            3,
            FrameError::UnknownDiscriminant {
                field: Field::Confidentiality,
                got: 3,
            },
        ),
        (
            11,
            3,
            FrameError::UnknownDiscriminant {
                field: Field::Integrity,
                got: 3,
            },
        ),
        (12, 0x40, FrameError::ProvenanceOutOfRange { got: 0x40 }),
        (
            29,
            4,
            FrameError::UnknownDiscriminant {
                field: Field::Authority,
                got: 4,
            },
        ),
        (
            30,
            5,
            FrameError::UnknownDiscriminant {
                field: Field::Derivation,
                got: 5,
            },
        ),
    ];
    for (at, byte, want) in cases {
        let mut b = body.clone();
        b[at] = byte;
        assert_eq!(GuestFrame::decode(&reframe(&b)), Err(want));
    }
}

#[test]
fn subject_length_and_encoding_are_checked() {
    let bytes = enc_g(&decide(0, "ab"));
    let body = body_of(&bytes);

    // Declared subject length (offset 11..13) over the bound.
    let mut long = body.clone();
    let over = u16::try_from(MAX_SUBJECT_LEN + 1).unwrap();
    long[11..13].copy_from_slice(&over.to_be_bytes());
    assert_eq!(
        GuestFrame::decode(&reframe(&long)),
        Err(FrameError::SubjectTooLong {
            len: MAX_SUBJECT_LEN + 1
        })
    );

    let mut bad = body.clone();
    bad[13] = 0xff;
    assert_eq!(
        GuestFrame::decode(&reframe(&bad)),
        Err(FrameError::SubjectNotUtf8)
    );
}

// ── Observe cannot lower a label (owner decision D2) ───────────────────────

/// `hi` is at least as restrictive as `lo` in every dimension.
fn dominates(hi: IFCLabel, lo: IFCLabel) -> bool {
    lo.flows_to(hi) && lo.freshness.leq(hi.freshness)
}

#[test]
fn observe_cannot_lower_a_label() {
    // The host holds an adversarial, web-derived taint. The guest reports the
    // most trusting label the lattice has. Through the wire and back, the host's
    // label must not move down in any dimension.
    let now = 1_700_000_000;
    let current = IFCLabel::web_content(now);
    let lowering_attempt = GuestFrame::Observe {
        seq: Seq::FIRST,
        label_raise: LabelRaise::new(IFCLabel::bottom()),
    };
    let decoded = GuestFrame::decode(&enc_g(&lowering_attempt)).unwrap();
    let GuestFrame::Observe { label_raise, .. } = decoded else {
        panic!("decoded as a different frame");
    };
    let after = label_raise.raise(current);
    assert_eq!(after, current, "a bottom report changes nothing");
    assert_eq!(after.integrity, IntegLevel::Adversarial);
    assert_eq!(after.authority, AuthorityLevel::NoAuthority);

    // A trusted user-prompt report cannot launder it either.
    let after = LabelRaise::new(IFCLabel::user_prompt(now)).raise(current);
    assert!(dominates(after, current));
    assert_eq!(after.integrity, IntegLevel::Adversarial);

    // And a genuine raise does raise.
    let after = LabelRaise::new(IFCLabel::secret(now)).raise(IFCLabel::user_prompt(now));
    assert_eq!(after.confidentiality, ConfLevel::Secret);
}

// ── DecisionId is single-use ───────────────────────────────────────────────

#[test]
fn a_decision_id_cannot_be_reused() {
    let mut ledger = DecisionLedger::new(EPOCH);
    let id = ledger.allow().unwrap();
    let wire = enc_h(&HostFrame::Verdict {
        seq: Seq::FIRST,
        verdict: Verdict::Allowed { decision_id: id },
    });

    // A guest replaying the frame holds two equal ids decoded from one set of
    // bytes. The type cannot stop that; the ledger must.
    let take = |bytes: &[u8]| match HostFrame::decode(bytes).unwrap() {
        HostFrame::Verdict {
            verdict: Verdict::Allowed { decision_id },
            ..
        } => decision_id,
        other => panic!("not an Allowed: {other:?}"),
    };
    let first = take(&wire);
    let replay = take(&wire);
    assert_eq!(first, replay);

    let spent = ledger.consume(first).expect("first use is good");
    assert_eq!(spent.decision(), 0);
    assert_eq!(
        ledger.consume(replay),
        Err(LedgerError::Retired { decision: 0 })
    );

    // A number the ledger never issued is a forgery, not a replay.
    assert_eq!(
        ledger.consume(DecisionId::mint(EPOCH, 99)),
        Err(LedgerError::NeverIssued { decision: 99 })
    );
}

#[test]
fn an_id_from_another_ledger_is_refused() {
    // A channel closes and its replacement starts a fresh ledger, which numbers
    // from zero again. Decision 0 from the old channel must not be decision 0
    // on the new one: that would be a replay across the reconnect that neither
    // ledger's bookkeeping can see on its own.
    let mut old = DecisionLedger::new(1);
    let stale = old.allow().unwrap();
    let wire = enc_h(&HostFrame::Verdict {
        seq: Seq::FIRST,
        verdict: Verdict::Allowed { decision_id: stale },
    });
    let mut new = DecisionLedger::new(2);
    let fresh = new.allow().unwrap();
    assert_eq!(fresh.number(), 0);

    let HostFrame::Verdict {
        verdict: Verdict::Allowed {
            decision_id: replayed,
        },
        ..
    } = HostFrame::decode(&wire).unwrap()
    else {
        panic!("not an Allowed");
    };
    assert_eq!(replayed.number(), 0, "same number as the fresh id");
    assert_eq!(
        new.consume(replayed),
        Err(LedgerError::ForeignEpoch {
            expected: 2,
            got: 1
        })
    );
    // The fresh id is unaffected.
    assert_eq!(new.consume(fresh).unwrap().epoch(), 2);

    // Same for approvals.
    let foreign = old.require_approval().unwrap();
    assert_eq!(
        new.redeem(foreign),
        Err(LedgerError::ForeignEpoch {
            expected: 2,
            got: 1
        })
    );
}

#[test]
fn an_approval_redeems_to_exactly_one_decision_once() {
    let mut ledger = DecisionLedger::new(EPOCH);
    let approval = ledger.require_approval().unwrap();
    let number = approval.number();
    let wire = enc_g(&GuestFrame::Redeem {
        seq: Seq::FIRST,
        approval_id: approval,
    });
    let take = |bytes: &[u8]| match GuestFrame::decode(bytes).unwrap() {
        GuestFrame::Redeem { approval_id, .. } => approval_id,
        other => panic!("not a Redeem: {other:?}"),
    };

    // The reserved decision is not usable before the approval is redeemed.
    assert_eq!(
        ledger.consume(DecisionId::mint(EPOCH, 0)),
        Err(LedgerError::AwaitingApproval { decision: 0 })
    );

    // Pending: the handle comes back.
    let Redemption::Pending(handle) = ledger.redeem(take(&wire)).unwrap() else {
        panic!("expected Pending");
    };
    assert_eq!(handle.number(), number);

    ledger.grant(number).unwrap();
    // A settled approval cannot be re-decided.
    assert_eq!(
        ledger.refuse(number),
        Err(LedgerError::ApprovalRetired { approval: number })
    );

    let Redemption::Granted(decision) = ledger.redeem(handle).unwrap() else {
        panic!("expected Granted");
    };
    assert_eq!(decision.number(), 0);

    // Redeeming the same approval again — from replayed bytes — is refused.
    assert_eq!(
        ledger.redeem(take(&wire)),
        Err(LedgerError::ApprovalRetired { approval: number })
    );
    assert_eq!(
        ledger.redeem(ApprovalId::mint(EPOCH, 55)),
        Err(LedgerError::ApprovalNeverIssued { approval: 55 })
    );

    // And the one decision it yielded is single-use like any other.
    assert!(ledger.consume(decision).is_ok());
    assert_eq!(
        ledger.consume(DecisionId::mint(EPOCH, 0)),
        Err(LedgerError::Retired { decision: 0 })
    );
}

#[test]
fn a_refused_approval_yields_nothing_and_retires_its_decision() {
    let mut ledger = DecisionLedger::new(EPOCH);
    let approval = ledger.require_approval().unwrap();
    ledger.refuse(approval.number()).unwrap();
    assert_eq!(ledger.redeem(approval), Ok(Redemption::Refused));
    assert_eq!(
        ledger.consume(DecisionId::mint(EPOCH, 0)),
        Err(LedgerError::Retired { decision: 0 })
    );
}

#[test]
fn live_ids_are_bounded() {
    let mut ledger = DecisionLedger::new(EPOCH);
    let mut held = Vec::new();
    for _ in 0..crate::host::MAX_LIVE {
        held.push(ledger.allow().unwrap());
    }
    assert_eq!(ledger.allow(), Err(LedgerError::TooManyLive));
    assert_eq!(ledger.require_approval(), Err(LedgerError::TooManyLive));
    // Consuming one frees one slot.
    let one = held.pop().unwrap();
    assert!(ledger.consume(one).is_ok());
    assert!(ledger.allow().is_ok());
}

// ── the host numbers the channel ──────────────────────────────────────────

#[test]
fn seq_gate_admits_only_the_next_number() {
    let mut gate = SeqGate::new();
    assert_eq!(
        gate.admit(Seq::new(1)),
        Err(SeqError::Skipped {
            expected: Seq::FIRST,
            got: Seq::new(1)
        })
    );
    assert_eq!(gate.admit(Seq::FIRST), Ok(()));
    assert_eq!(
        gate.admit(Seq::FIRST),
        Err(SeqError::Replayed {
            expected: Seq::new(1),
            got: Seq::FIRST
        })
    );
    assert_eq!(gate.admit(Seq::new(1)), Ok(()));
    assert_eq!(gate.expected(), Some(Seq::new(2)));
    assert_eq!(Seq::new(u64::MAX).next(), None);
}

// ── properties ─────────────────────────────────────────────────────────────

fn arb_label() -> impl Strategy<Value = IFCLabel> {
    (
        prop::sample::select(CONF_ALL.to_vec()),
        prop::sample::select(INTEG_ALL.to_vec()),
        0u8..0x40,
        any::<u64>(),
        any::<u64>(),
        prop::sample::select(AUTHORITY_ALL.to_vec()),
        prop::sample::select(DERIVATION_ALL.to_vec()),
    )
        .prop_map(|(c, i, p, o, t, a, d)| label(c, i, p, o, t, a, d))
}

fn arb_guest_frame() -> impl Strategy<Value = GuestFrame> {
    prop_oneof![
        (
            any::<u64>(),
            prop::sample::select(Operation::ALL.to_vec()),
            proptest::string::string_regex(".{0,64}").unwrap(),
            any::<[u8; 32]>(),
        )
            .prop_map(|(s, op, subj, d)| GuestFrame::Decide {
                seq: Seq::new(s),
                op,
                subject: Subject::new(subj).unwrap(),
                args_digest: ArgsDigest::new(d),
            }),
        (any::<u64>(), arb_label()).prop_map(|(s, l)| GuestFrame::Observe {
            seq: Seq::new(s),
            label_raise: LabelRaise::new(l),
        }),
        (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(s, e, a)| GuestFrame::Redeem {
            seq: Seq::new(s),
            approval_id: ApprovalId::mint(e, a),
        }),
    ]
}

fn arb_host_frame() -> impl Strategy<Value = HostFrame> {
    prop_oneof![
        (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(s, e, d)| HostFrame::Verdict {
            seq: Seq::new(s),
            verdict: Verdict::Allowed {
                decision_id: DecisionId::mint(e, d),
            },
        }),
        (any::<u64>(), prop::sample::select(DenyReason::ALL.to_vec())).prop_map(|(s, r)| {
            HostFrame::Verdict {
                seq: Seq::new(s),
                verdict: Verdict::Denied { reason: r },
            }
        }),
        (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(s, e, a)| HostFrame::Verdict {
            seq: Seq::new(s),
            verdict: Verdict::ApprovalRequired {
                approval_id: ApprovalId::mint(e, a),
            },
        }),
        any::<u64>().prop_map(|s| HostFrame::Observed { seq: Seq::new(s) }),
    ]
}

proptest! {
    #[test]
    fn prop_guest_round_trip(f in arb_guest_frame()) {
        let bytes = f.encode().unwrap();
        let back = GuestFrame::decode(&bytes).unwrap();
        prop_assert_eq!(back.encode().unwrap(), bytes);
        prop_assert_eq!(back, f);
    }

    #[test]
    fn prop_host_round_trip(f in arb_host_frame()) {
        let bytes = f.encode().unwrap();
        let back = HostFrame::decode(&bytes).unwrap();
        prop_assert_eq!(back.encode().unwrap(), bytes);
        prop_assert_eq!(back, f);
    }

    /// Any bytes: no panic, and anything accepted is canonical.
    #[test]
    fn prop_decode_is_total_and_canonical(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(f) = GuestFrame::decode(&bytes) {
            prop_assert_eq!(f.encode().unwrap(), bytes.clone());
        }
        if let Ok(f) = HostFrame::decode(&bytes) {
            prop_assert_eq!(f.encode().unwrap(), bytes.clone());
        }
        let _ = GuestFrame::decode_body(&bytes);
        let _ = HostFrame::decode_body(&bytes);
    }

    /// Mutating one byte of a valid frame never panics, and if it still
    /// decodes, it re-encodes to the mutated bytes.
    #[test]
    fn prop_single_byte_mutation(f in arb_guest_frame(), at in any::<prop::sample::Index>(), b in any::<u8>()) {
        let mut bytes = f.encode().unwrap();
        let i = at.index(bytes.len());
        bytes[i] = b;
        if let Ok(g) = GuestFrame::decode(&bytes) {
            prop_assert_eq!(g.encode().unwrap(), bytes);
        }
    }

    /// D2: for every label the host holds and every label a guest reports, the
    /// result is at least as restrictive as what the host held.
    #[test]
    fn prop_observe_never_lowers(current in arb_label(), reported in arb_label()) {
        let after = LabelRaise::new(reported).raise(current);
        prop_assert!(dominates(after, current));
        // And the raise is exactly the join: it adds nothing the report did not say.
        prop_assert_eq!(after, current.join(reported));
    }
}
