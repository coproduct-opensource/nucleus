//! Properties of applying a patch, over generated checkpoints.

use std::collections::BTreeSet;

use nucleus_weight_patch::{
    Applier, DeclaredWrites, Dtype, Indexer, Op, PatchProgram, Scalar, WriteVerdict, check_writes,
    write_checkpoint,
};
use proptest::prelude::*;

/// One generated tensor: its element type and its bytes.
#[derive(Clone, Debug)]
struct Tensor {
    dtype: Dtype,
    bytes: Vec<u8>,
    elements: u64,
}

fn tensor() -> impl Strategy<Value = Tensor> {
    (
        any::<bool>(),
        prop::collection::vec(-1000.0f32..1000.0, 1..40),
    )
        .prop_map(|(wide, values)| {
            let elements = u64::try_from(values.len()).unwrap();
            if wide {
                Tensor {
                    dtype: Dtype::F32,
                    bytes: values.iter().flat_map(|v| v.to_le_bytes()).collect(),
                    elements,
                }
            } else {
                // Truncate each value to its high 16 bits, stored little-endian.
                Tensor {
                    dtype: Dtype::Bf16,
                    bytes: values
                        .iter()
                        .flat_map(|v| {
                            let [hi, lo, _, _] = v.to_bits().to_be_bytes();
                            [lo, hi]
                        })
                        .collect(),
                    elements,
                }
            }
        })
}

/// A checkpoint of 1..6 tensors, which of them a patch targets (at least one),
/// and the value it adds.
fn case() -> impl Strategy<Value = (Vec<Tensor>, Vec<bool>, f32)> {
    prop::collection::vec(tensor(), 1..6).prop_flat_map(|tensors| {
        let n = tensors.len();
        (
            Just(tensors),
            prop::collection::vec(any::<bool>(), n).prop_map(|mut mask| {
                if !mask.contains(&true) {
                    mask[0] = true;
                }
                mask
            }),
            -4.0f32..4.0,
        )
    })
}

fn name(i: usize) -> String {
    format!("t{i}")
}

fn file(tensors: &[Tensor]) -> Vec<u8> {
    let names: Vec<String> = (0..tensors.len()).map(name).collect();
    let shapes: Vec<[u64; 1]> = tensors.iter().map(|t| [t.elements]).collect();
    let entries: Vec<(&str, Dtype, &[u64], &[u8])> = tensors
        .iter()
        .enumerate()
        .map(|(i, t)| {
            (
                names[i].as_str(),
                t.dtype,
                &shapes[i][..],
                t.bytes.as_slice(),
            )
        })
        .collect();
    let mut out = Vec::new();
    write_checkpoint(&entries, &mut out).unwrap();
    out
}

fn program(mask: &[bool], value: f32) -> PatchProgram {
    let ops = mask
        .iter()
        .enumerate()
        .filter(|(_, on)| **on)
        .map(|(i, _)| Op::AddScalar {
            tensor: name(i),
            value: Scalar::from_f32(value).unwrap(),
        })
        .collect();
    PatchProgram::new(ops).unwrap()
}

proptest! {
    /// The same base and program give the same bytes and the same digests.
    #[test]
    fn applying_is_a_function((tensors, mask, value) in case()) {
        let base = file(&tensors);
        let p = program(&mask, value);
        let (mut one, mut two) = (Vec::new(), Vec::new());
        let a = Applier::new(&p).file(&*base, &mut one).unwrap().finish().unwrap();
        let b = Applier::new(&p).file(&*base, &mut two).unwrap().finish().unwrap();
        prop_assert_eq!(&one, &two);
        prop_assert_eq!(a, b);
    }

    /// Whoever re-reads the output measures the digest the applier reported.
    #[test]
    fn the_reported_output_is_what_was_written((tensors, mask, value) in case()) {
        let base = file(&tensors);
        let p = program(&mask, value);
        let mut out = Vec::new();
        let applied = Applier::new(&p).file(&*base, &mut out).unwrap().finish().unwrap();
        let reread = Indexer::start().file(&*out).unwrap().finish();
        prop_assert_eq!(&reread, applied.output());
        let base_reread = Indexer::start().file(&*base).unwrap().finish();
        prop_assert_eq!(&base_reread, applied.base());
    }

    /// Every measured write is a tensor the program named, so a declaration of
    /// the program's targets is always satisfied.
    #[test]
    fn measured_writes_are_within_the_targets((tensors, mask, value) in case()) {
        let base = file(&tensors);
        let p = program(&mask, value);
        let applied = Applier::new(&p).file(&*base, std::io::sink()).unwrap().finish().unwrap();
        let measured = applied.diff().unwrap();
        let targets: BTreeSet<&str> = p.targets();
        for write in measured.writes() {
            prop_assert!(targets.contains(write.name.as_str()));
        }
        let declared = DeclaredWrites::new(targets.iter().copied()).unwrap();
        prop_assert!(matches!(check_writes(&measured, &declared), WriteVerdict::Within(_)));
    }

    /// A declaration that leaves out a tensor that was written is refused, and
    /// the refusal names exactly the writes it left out.
    #[test]
    fn a_write_left_out_of_the_declaration_is_named((tensors, mask, value) in case()) {
        let base = file(&tensors);
        let p = program(&mask, value);
        let applied = Applier::new(&p).file(&*base, std::io::sink()).unwrap().finish().unwrap();
        let measured = applied.diff().unwrap();
        let written: Vec<String> = measured.writes().into_iter().map(|w| w.name).collect();
        // Nothing to leave out when every addition rounded back to its start.
        prop_assume!(!written.is_empty());
        let left_out = written[0].clone();
        // Declare every other written tensor, plus a name the checkpoint lacks
        // so the declaration is never empty.
        let declared = DeclaredWrites::new(
            written.iter().skip(1).cloned().chain(["not-in-the-checkpoint".to_owned()]),
        )
        .unwrap();
        match check_writes(&measured, &declared) {
            WriteVerdict::Outside { undeclared, writes } => {
                prop_assert_eq!(undeclared.into_iter().collect::<Vec<_>>(), vec![left_out]);
                prop_assert_eq!(writes.len(), written.len());
            }
            WriteVerdict::Within(_) => prop_assert!(false, "an undeclared write passed"),
        }
    }
}
