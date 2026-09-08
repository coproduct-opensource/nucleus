//! The argv predicate at the spawn boundary (#2573).
//!
//! Two functions spawn a mediated process: `Executor::spawn_checked` in the
//! nucleus crate, and `RealEffects::run_argv`, the sealed home it delegates
//! to. Before this module each kept its own idea of what argv it would
//! refuse — the executor rejected an empty argv, the sealed home rejected
//! nothing and let `Command::spawn` fail however the OS pleased — and the
//! comment "reproduces `Executor::spawn_checked` exactly" was the only thing
//! binding the two. This is the ONE predicate both apply, in one function
//! text, so parity is by construction and the Kani harness below proves the
//! predicate itself is fail-closed on every malformed shape it names.
//!
//! What it refuses:
//!
//! * an empty argv — nothing to spawn;
//! * an empty program — `Command::new("")` is an ENOENT with an empty name,
//!   which is a confusing failure and not a spawn the caller authorized;
//! * a NUL byte anywhere in the program or an argument — `execve(2)` takes
//!   C strings, so a NUL silently truncates the string it appears in. An
//!   argv the kernel would execute differently from how it was checked is
//!   the definition of a check bypass, so this is refused up front with a
//!   named reason rather than left to `std`'s `InvalidInput`.
//!
//! The predicate is over bytes (`check_argv_bytes`) so the proof does not
//! need to construct `String`s, which are Kani-hostile; the `&str` entry
//! points are thin wrappers.

use core::fmt;

/// Prefix every argv refusal carries, in the executor's `CommandDenied`
/// reason and in the sealed home's `io::Error` message alike, so a parity
/// test can recognise the refusal on either side without parsing the rest.
pub const ARGV_REFUSED_PREFIX: &str = "argv refused: ";

/// Why an argv was refused at the spawn boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgvRejection {
    /// No program at all.
    EmptyArgv,
    /// `argv[0]` is the empty string.
    EmptyProgram,
    /// `argv[0]` contains a NUL byte.
    NulInProgram,
    /// Argument `index` (0-based, after the program) contains a NUL byte.
    NulInArg {
        /// Position among the arguments, not counting the program.
        index: usize,
    },
}

impl fmt::Display for ArgvRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyArgv => f.write_str("empty command"),
            Self::EmptyProgram => f.write_str("empty program name"),
            Self::NulInProgram => f.write_str("NUL byte in program name"),
            Self::NulInArg { index } => write!(f, "NUL byte in argument {index}"),
        }
    }
}

impl std::error::Error for ArgvRejection {}

/// The refusal as the sealed home's error: `InvalidInput`, message prefixed by
/// [`ARGV_REFUSED_PREFIX`], so the parity test recognises it on that side
/// exactly as it recognises the executor's `CommandDenied` reason.
impl From<ArgvRejection> for std::io::Error {
    fn from(rejection: ArgvRejection) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, rejection.message())
    }
}

impl ArgvRejection {
    /// The refusal as the message both spawn boundaries emit.
    pub fn message(&self) -> String {
        format!("{ARGV_REFUSED_PREFIX}{self}")
    }
}

/// The predicate over raw bytes. This is the function the proof is about.
pub fn check_argv_bytes<'a, I>(program: &[u8], args: I) -> Result<(), ArgvRejection>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    if program.is_empty() {
        return Err(ArgvRejection::EmptyProgram);
    }
    if program.contains(&0) {
        return Err(ArgvRejection::NulInProgram);
    }
    for (index, arg) in args.into_iter().enumerate() {
        if arg.contains(&0) {
            return Err(ArgvRejection::NulInArg { index });
        }
    }
    Ok(())
}

/// The predicate over an already-split `program` + `args`, the shape
/// `RealEffects::run_argv` receives.
pub fn check_argv(program: &str, args: &[String]) -> Result<(), ArgvRejection> {
    check_argv_bytes(program.as_bytes(), args.iter().map(|a| a.as_bytes()))
}

/// The predicate over a whole argv, the shape the executor receives. On
/// success returns the split the caller was about to make anyway, so an
/// accepted argv is never re-split by hand (and `split_first().unwrap()`
/// disappears from the spawn path).
pub fn split_and_check(argv: &[String]) -> Result<(&str, &[String]), ArgvRejection> {
    let (program, args) = argv.split_first().ok_or(ArgvRejection::EmptyArgv)?;
    check_argv(program, args)?;
    Ok((program.as_str(), args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn accepts_a_plain_argv_and_returns_the_split() {
        let argv = s(&["echo", "hello", "world"]);
        let (program, args) = split_and_check(&argv).unwrap();
        assert_eq!(program, "echo");
        assert_eq!(args, &argv[1..]);
    }

    #[test]
    fn refuses_each_named_shape_with_the_right_reason() {
        assert_eq!(split_and_check(&[]), Err(ArgvRejection::EmptyArgv));
        assert_eq!(
            split_and_check(&s(&["", "x"])),
            Err(ArgvRejection::EmptyProgram)
        );
        assert_eq!(
            split_and_check(&s(&["ec\0ho", "x"])),
            Err(ArgvRejection::NulInProgram)
        );
        assert_eq!(
            split_and_check(&s(&["echo", "ok", "bad\0"])),
            Err(ArgvRejection::NulInArg { index: 1 })
        );
    }

    #[test]
    fn program_shape_is_checked_before_arguments() {
        // A NUL in both: the program wins, so the reason names the earliest
        // element the kernel would misread.
        assert_eq!(
            check_argv("a\0", &s(&["b\0"])),
            Err(ArgvRejection::NulInProgram)
        );
    }

    #[test]
    fn every_message_carries_the_shared_prefix() {
        for r in [
            ArgvRejection::EmptyArgv,
            ArgvRejection::EmptyProgram,
            ArgvRejection::NulInProgram,
            ArgvRejection::NulInArg { index: 3 },
        ] {
            assert!(r.message().starts_with(ARGV_REFUSED_PREFIX), "{r:?}");
        }
        assert_eq!(
            ArgvRejection::NulInArg { index: 3 }.message(),
            "argv refused: NUL byte in argument 3"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC — the argv predicate is fail-closed on every malformed shape
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const P: usize = 3;
    const A: usize = 2;

    /// **`proof_argv_check_fail_closed`.** Over every program of length ≤ 3
    /// and every two arguments of length ≤ 2 (bytes fully symbolic), the
    /// predicate accepts *exactly* the argvs with a non-empty program and no
    /// NUL byte anywhere — so every shape `execve(2)` would silently
    /// truncate, and the empty program, is refused, and nothing well-formed
    /// is. `kani::cover!` on each verdict rules out a vacuous pass.
    #[kani::proof]
    #[kani::unwind(4)]
    fn proof_argv_check_fail_closed() {
        let program: [u8; P] = kani::any();
        let plen: usize = kani::any();
        kani::assume(plen <= P);
        let a0: [u8; A] = kani::any();
        let l0: usize = kani::any();
        kani::assume(l0 <= A);
        let a1: [u8; A] = kani::any();
        let l1: usize = kani::any();
        kani::assume(l1 <= A);

        let p = &program[..plen];
        let args: [&[u8]; 2] = [&a0[..l0], &a1[..l1]];

        let verdict = check_argv_bytes(p, args.iter().copied());

        let has_nul = |b: &[u8]| b.iter().any(|&x| x == 0);
        let malformed = p.is_empty() || has_nul(p) || has_nul(args[0]) || has_nul(args[1]);

        // Fail-closed: malformed ⟹ refused. Complete: well-formed ⟹ accepted.
        assert_eq!(verdict.is_err(), malformed);

        // The reason names the earliest element the kernel would misread.
        match verdict {
            Err(ArgvRejection::EmptyProgram) => assert!(p.is_empty()),
            Err(ArgvRejection::NulInProgram) => assert!(has_nul(p)),
            Err(ArgvRejection::NulInArg { index }) => {
                assert!(!p.is_empty() && !has_nul(p));
                assert!(has_nul(args[index]));
                assert!(index == 0 || !has_nul(args[0]));
            }
            Err(ArgvRejection::EmptyArgv) => unreachable!("a split argv always has a program"),
            Ok(()) => {}
        }

        kani::cover!(verdict.is_ok(), "a well-formed argv is accepted");
        kani::cover!(verdict == Err(ArgvRejection::EmptyProgram));
        kani::cover!(verdict == Err(ArgvRejection::NulInProgram));
        kani::cover!(verdict == Err(ArgvRejection::NulInArg { index: 1 }));
    }
}
