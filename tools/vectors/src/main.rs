//! Generator for the shared attestation test vectors consumed by the
//! Solidity, Solana, and fullnode bridge verifiers.
//!
//! `cargo run --release` (no args) regenerates both copies of the vector
//! file: `vectors/attestations.json` in this repo and
//! `../fullnode/crates/randprotocol-core/src/bridge/vectors.json`.
//! `cargo run --release -- --check` asserts the two on-disk copies are
//! byte-identical and exits 1 otherwise.
//! `cargo run --release -- --out <path>` writes a single copy to `<path>`
//! instead of the two default locations.

mod cases;
mod types;

use std::fs;
use std::path::{Path, PathBuf};

fn bridge_repo_out() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/attestations.json")
}

fn fullnode_out() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fullnode/crates/randprotocol-core/src/bridge/vectors.json")
}

fn render() -> String {
    let file = cases::build();
    serde_json::to_string_pretty(&file).expect("vectors file serializes") + "\n"
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut check = false;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => check = true,
            "--out" => {
                i += 1;
                let path = args
                    .get(i)
                    .unwrap_or_else(|| panic!("--out requires a path argument"));
                out = Some(PathBuf::from(path));
            }
            other => panic!("unrecognized argument: {other}"),
        }
        i += 1;
    }

    if check {
        // Compare both files against a *freshly rendered* copy, not just
        // against each other: two identical files can still both be stale,
        // which is exactly the failure `--check` exists to catch (a case
        // added to the generator without re-running it).
        let expected = render();
        let mut drifted = Vec::new();
        for path in [bridge_repo_out(), fullnode_out()] {
            match fs::read_to_string(&path) {
                Ok(found) if found == expected => {}
                Ok(_) => drifted.push(format!("{}: differs from the generator's output", path.display())),
                Err(e) => drifted.push(format!("{}: {e}", path.display())),
            }
        }
        if drifted.is_empty() {
            println!(
                "OK: {} and {} both match the generator's output",
                bridge_repo_out().display(),
                fullnode_out().display()
            );
            return;
        }
        eprintln!("MISMATCH: re-run `cargo run --release` in tools/vectors");
        for line in &drifted {
            eprintln!("  {line}");
        }
        std::process::exit(1);
    }

    let json = render();

    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, &json).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
        println!("wrote {}", path.display());
        return;
    }

    for path in [bridge_repo_out(), fullnode_out()] {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, &json).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
        println!("wrote {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use randprotocol_core::bridge::{verify, GuardianSet, IndexError, VerifyError};

    /// Self-check mirroring the fullnode's `bridge::vectors` test: every
    /// signature-level vector is independently re-verified with
    /// `randprotocol_core::bridge::verify` before shipping.
    ///
    /// `unknown_set` is intentionally excluded: `verify` takes an
    /// already-resolved `GuardianSet`, not an index, so "no set at this
    /// index" is a set-*resolution* concern that belongs to the ledger
    /// (`BridgeState::check_attest`, Task C2), which maps it to
    /// `VerifyError::UnknownGuardianSet`. Asserting it here against the
    /// vector's own `sets` would be tautological (true by construction of
    /// this very generator).
    #[test]
    fn every_signature_level_vector_matches_verify() {
        let file = crate::cases::build();
        let signature_level = [
            "ok",
            "no_quorum",
            "index_order",
            "index_out_of_range",
            "bad_signature",
            "high_s",
            "wrong_guardian",
            "set_expired",
            "bad_version",
        ];
        let mut checked = 0;
        for v in &file.vectors {
            if !signature_level.contains(&v.expect.as_str()) {
                continue;
            }
            checked += 1;
            let bytes = hex::decode(&v.attestation).unwrap();
            let set_entry = v.sets.iter().find(|s| s.index == v.guardian_set_index);
            let set_entry = set_entry.unwrap_or_else(|| panic!("{}: missing set {}", v.name, v.guardian_set_index));
            let keys = set_entry
                .keys
                .iter()
                .map(|k| {
                    let b = hex::decode(k).unwrap();
                    let arr: [u8; 20] = b.try_into().unwrap();
                    arr
                })
                .collect();
            let set = GuardianSet {
                keys,
                expires_at: set_entry.expires_at,
            };
            let result = verify(&bytes, &set, file.now);
            match v.expect.as_str() {
                "ok" => {
                    let (_, d) = result.unwrap_or_else(|e| panic!("{}: expected ok, got {e:?}", v.name));
                    assert_eq!(hex::encode(d), v.digest, "{}: digest mismatch", v.name);
                }
                "no_quorum" => assert!(
                    matches!(result, Err(VerifyError::Index(IndexError::NoQuorum { .. }))),
                    "{}: {result:?}",
                    v.name
                ),
                "index_order" => assert!(
                    matches!(result, Err(VerifyError::Index(IndexError::IndexOrder))),
                    "{}: {result:?}",
                    v.name
                ),
                "index_out_of_range" => assert!(
                    matches!(result, Err(VerifyError::Index(IndexError::IndexOutOfRange))),
                    "{}: {result:?}",
                    v.name
                ),
                "bad_signature" => assert!(
                    matches!(result, Err(VerifyError::BadSignature(_))),
                    "{}: {result:?}",
                    v.name
                ),
                "high_s" => assert!(matches!(result, Err(VerifyError::HighS(_))), "{}: {result:?}", v.name),
                "wrong_guardian" => assert!(
                    matches!(result, Err(VerifyError::WrongGuardian(_))),
                    "{}: {result:?}",
                    v.name
                ),
                "set_expired" => assert!(matches!(result, Err(VerifyError::SetExpired)), "{}: {result:?}", v.name),
                "bad_version" => assert!(
                    matches!(
                        result,
                        Err(VerifyError::Codec(randprotocol_core::bridge::CodecError::BadVersion))
                    ),
                    "{}: {result:?}",
                    v.name
                ),
                other => panic!("unhandled expect: {other}"),
            }
        }
        assert!(checked >= 10, "expected at least 10 signature-level vectors, saw {checked}");
    }
}
