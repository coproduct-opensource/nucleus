//! The archive: the patch programs and evaluation transcripts a release
//! record's receipts name by digest.
//!
//! Receipts bind digests. To replay a patch or recompute a score, a verifier
//! needs the bytes. They are filed here under the digest the receipt names
//! and checked against it when read, so the archive needs no trust of its own.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nucleus_release_gate::eval::{ItemOutcome, OutcomeError, transcript_digest};
use nucleus_release_gate::keys::ContentDigest;
use nucleus_weight_patch::{PatchProgram, ProgramDigest};

/// Why the archive could not supply, or take in, an item.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// The archive cannot be read or written.
    #[error("archive: {0}")]
    Io(#[from] io::Error),
    /// The archive has nothing under this digest.
    #[error("the archive has no {kind} {digest}")]
    Absent {
        /// What was asked for.
        kind: &'static str,
        /// Its digest.
        digest: String,
    },
    /// The bytes filed under a digest do not parse.
    #[error("the {kind} filed under {digest} does not parse: {detail}")]
    Malformed {
        /// What it should be.
        kind: &'static str,
        /// The digest it is filed under.
        digest: String,
        /// The parser's message.
        detail: String,
    },
    /// The bytes filed under a digest have another digest.
    #[error("the {kind} filed under {digest} has another digest")]
    Mismatch {
        /// What it is.
        kind: &'static str,
        /// The digest it is filed under.
        digest: String,
    },
    /// A transcript could not be put in canonical form.
    #[error(transparent)]
    Outcome(#[from] OutcomeError),
}

/// A directory of programs and transcripts, each under its digest.
#[derive(Clone, Debug)]
pub struct Archive {
    dir: PathBuf,
}

fn read(path: &Path, kind: &'static str, digest: &str) -> Result<String, ArchiveError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(ArchiveError::Absent {
            kind,
            digest: digest.to_owned(),
        }),
        Err(e) => Err(e.into()),
    }
}

impl Archive {
    /// The archive rooted at `dir`.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::Io`] if its directories cannot be created.
    pub fn open(dir: &Path) -> Result<Self, ArchiveError> {
        fs::create_dir_all(dir.join("programs"))?;
        fs::create_dir_all(dir.join("transcripts"))?;
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    fn program_path(&self, digest: ProgramDigest) -> PathBuf {
        self.dir
            .join("programs")
            .join(format!("{}.json", digest.to_hex()))
    }

    fn transcript_path(&self, digest: ContentDigest) -> PathBuf {
        self.dir
            .join("transcripts")
            .join(format!("{}.jsonl", digest.to_hex()))
    }

    /// Files `program` under its digest.
    ///
    /// # Errors
    ///
    /// [`ArchiveError`] if it cannot be written.
    pub fn put_program(&self, program: &PatchProgram) -> Result<ProgramDigest, ArchiveError> {
        let digest = program.digest();
        let json = serde_json::to_string(program).map_err(|e| ArchiveError::Malformed {
            kind: "program",
            digest: digest.to_hex(),
            detail: e.to_string(),
        })?;
        fs::write(self.program_path(digest), json)?;
        Ok(digest)
    }

    /// The program with this digest.
    ///
    /// # Errors
    ///
    /// [`ArchiveError`] if it is absent, does not parse, or has another
    /// digest.
    pub fn program(&self, digest: ProgramDigest) -> Result<PatchProgram, ArchiveError> {
        let hex = digest.to_hex();
        let text = read(&self.program_path(digest), "program", &hex)?;
        let program: PatchProgram =
            serde_json::from_str(&text).map_err(|e| ArchiveError::Malformed {
                kind: "program",
                digest: hex.clone(),
                detail: e.to_string(),
            })?;
        if program.digest() != digest {
            return Err(ArchiveError::Mismatch {
                kind: "program",
                digest: hex,
            });
        }
        Ok(program)
    }

    /// Files `outcomes` under their transcript digest, one JSON line each.
    ///
    /// # Errors
    ///
    /// [`ArchiveError`] if they cannot be serialized or written.
    pub fn put_transcript(&self, outcomes: &[ItemOutcome]) -> Result<ContentDigest, ArchiveError> {
        let digest = transcript_digest(outcomes)?;
        let mut text = String::new();
        for outcome in outcomes {
            let line = serde_json::to_string(outcome).map_err(|e| ArchiveError::Malformed {
                kind: "transcript",
                digest: digest.to_hex(),
                detail: e.to_string(),
            })?;
            text.push_str(&line);
            text.push('\n');
        }
        fs::write(self.transcript_path(digest), text)?;
        Ok(digest)
    }

    /// The transcript with this digest.
    ///
    /// # Errors
    ///
    /// [`ArchiveError`] if it is absent, does not parse, or has another
    /// digest.
    pub fn transcript(&self, digest: ContentDigest) -> Result<Vec<ItemOutcome>, ArchiveError> {
        let hex = digest.to_hex();
        let text = read(&self.transcript_path(digest), "transcript", &hex)?;
        let mut outcomes = Vec::new();
        for line in text.lines() {
            outcomes.push(
                serde_json::from_str(line).map_err(|e| ArchiveError::Malformed {
                    kind: "transcript",
                    digest: hex.clone(),
                    detail: e.to_string(),
                })?,
            );
        }
        if transcript_digest(&outcomes)? != digest {
            return Err(ArchiveError::Mismatch {
                kind: "transcript",
                digest: hex,
            });
        }
        Ok(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_release_gate::eval::Outcome;
    use nucleus_weight_patch::{Op, Scalar};

    fn program(tensors: &[&str]) -> PatchProgram {
        PatchProgram::new(
            tensors
                .iter()
                .map(|tensor| Op::AddScalar {
                    tensor: (*tensor).to_owned(),
                    value: Scalar::from_f32(0.5).unwrap(),
                })
                .collect(),
        )
        .unwrap()
    }

    fn outcomes(correct: bool) -> Vec<ItemOutcome> {
        let answer = |correct| Outcome {
            correct,
            token_limit: false,
            output: ContentDigest::from_bytes([0; 32]),
        };
        vec![ItemOutcome {
            task: "math".to_owned(),
            item: "m0".to_owned(),
            seed: 0,
            base: answer(false),
            candidate: answer(correct),
        }]
    }

    #[test]
    fn what_is_filed_is_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let archive = Archive::open(dir.path()).unwrap();
        let p = program(&["a", "b"]);
        assert_eq!(
            archive.program(archive.put_program(&p).unwrap()).unwrap(),
            p
        );
        let t = outcomes(true);
        assert_eq!(
            archive
                .transcript(archive.put_transcript(&t).unwrap())
                .unwrap(),
            t
        );
    }

    #[test]
    fn nothing_filed_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let archive = Archive::open(dir.path()).unwrap();
        assert!(matches!(
            archive.program(program(&["a"]).digest()),
            Err(ArchiveError::Absent {
                kind: "program",
                ..
            })
        ));
        assert!(matches!(
            archive.transcript(transcript_digest(&outcomes(true)).unwrap()),
            Err(ArchiveError::Absent {
                kind: "transcript",
                ..
            })
        ));
    }

    #[test]
    fn a_program_with_the_same_effect_and_another_digest_is_not_the_program() {
        let dir = tempfile::tempdir().unwrap();
        let archive = Archive::open(dir.path()).unwrap();
        // The same two operations in the other order: the same output on any
        // checkpoint, and not the program a manifest naming `named` bound.
        let named = archive.put_program(&program(&["a", "b"])).unwrap();
        let reordered = serde_json::to_string(&program(&["b", "a"])).unwrap();
        fs::write(archive.program_path(named), reordered).unwrap();
        assert!(matches!(
            archive.program(named),
            Err(ArchiveError::Mismatch {
                kind: "program",
                ..
            })
        ));
    }

    #[test]
    fn a_transcript_filed_under_another_digest_is_not_the_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let archive = Archive::open(dir.path()).unwrap();
        let named = archive.put_transcript(&outcomes(false)).unwrap();
        let other = archive.put_transcript(&outcomes(true)).unwrap();
        fs::copy(
            archive.transcript_path(other),
            archive.transcript_path(named),
        )
        .unwrap();
        assert!(matches!(
            archive.transcript(named),
            Err(ArchiveError::Mismatch {
                kind: "transcript",
                ..
            })
        ));
    }
}
