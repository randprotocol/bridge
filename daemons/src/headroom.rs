//! How many guardians are signing, against how many the quorum needs (BR-402):
//! `rand-bridge-audit --headroom`. Read-only.
//!
//! A registered set of `n` needs `n * 2 / 3 + 1` signatures. The spare is the
//! number of guardians that can stop before nothing is signed. A guardian
//! counts when its API answers `/v1/health`, the address it answers with is in
//! the registered set, and its signing is not paused. Two origins answering as
//! one guardian count once. For mints the chain also needs a quorum of
//! Dilithium2 co-signatures: a guardian counts for that only when its health
//! names a PQ key that is the registered one at its own index. A guardian
//! whose build does not report its PQ key is counted as unknown, never as
//! present.

use std::collections::BTreeMap;

use crate::api::Health;

/// `n * 2 / 3 + 1`: the quorum of a set of `n`, on every verifier.
pub fn quorum(n: usize) -> usize {
    n * 2 / 3 + 1
}

/// What one configured origin answered.
#[derive(Clone, Debug)]
pub struct Probe {
    /// The origin as configured (host and port; guardian APIs carry no secret).
    pub origin: String,
    pub health: Result<Health, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// Counted: registered, answering, not paused. `pq`: whether its PQ key is the registered
    /// one at its index (`None`: its build does not say).
    Signing { index: usize, pq: Option<bool>, held: usize, deferred: usize },
    Paused { index: usize, reason: String },
    /// It answers as an address the chain does not have in its set.
    NotRegistered { guardian: String },
    /// A second origin answering as a guardian already counted.
    Duplicate { index: usize },
    Down { error: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub registered: usize,
    pub quorum: usize,
    pub lines: Vec<(String, Line)>,
    /// Registered guardians no configured origin answered as, by index.
    pub missing: Vec<usize>,
    pub signing: usize,
    /// The PQ set's size and quorum; `None` on a chain without the co-signature.
    pub pq: Option<PqReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqReport {
    pub registered: usize,
    pub quorum: usize,
    /// Signing guardians whose PQ key is the registered one.
    pub signing: usize,
    /// Signing guardians whose build does not report a PQ key.
    pub unknown: usize,
}

impl Report {
    /// Guardians that can stop before releases stop; negative: below quorum.
    pub fn spare(&self) -> i64 {
        self.signing as i64 - self.quorum as i64
    }
    /// The same for mints, counting only PQ keys known to be right.
    pub fn pq_spare(&self) -> Option<i64> {
        self.pq.as_ref().map(|p| p.signing as i64 - p.quorum as i64)
    }
    /// Whether both spares are at least `min_spare`. Unknown PQ keys do not count.
    pub fn ok(&self, min_spare: i64) -> bool {
        self.spare() >= min_spare && self.pq_spare().is_none_or(|s| s >= min_spare)
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// What a guardian's health names as its PQ key: the sha256 of the public key, hex.
pub fn pq_key_id(public_key: &[u8]) -> String {
    sha256_hex(public_key)
}

/// `guardians`: the registered ECDSA set, in index order. `pq_guardians`: the
/// registered PQ keys, index-aligned with it; empty on a chain without them.
pub fn report(guardians: &[[u8; 20]], pq_guardians: &[Vec<u8>], probes: &[Probe]) -> Report {
    let mut seen: BTreeMap<usize, ()> = BTreeMap::new();
    let mut lines = Vec::new();
    let (mut signing, mut pq_signing, mut pq_unknown) = (0, 0, 0);
    for p in probes {
        let line = match &p.health {
            Err(e) => Line::Down { error: e.clone() },
            Ok(h) => {
                let address = h.guardian.trim_start_matches("0x").to_ascii_lowercase();
                match guardians.iter().position(|g| hex::encode(g) == address) {
                    None => Line::NotRegistered { guardian: address },
                    Some(index) if seen.contains_key(&index) => Line::Duplicate { index },
                    Some(index) => {
                        seen.insert(index, ());
                        match &h.paused {
                            Some(reason) => Line::Paused { index, reason: reason.clone() },
                            None => {
                                signing += 1;
                                let pq = h.pq_key_sha256.as_ref().map(|id| {
                                    pq_guardians.get(index).is_some_and(|k| pq_key_id(k) == id.to_ascii_lowercase())
                                });
                                match pq {
                                    Some(true) => pq_signing += 1,
                                    None => pq_unknown += 1,
                                    Some(false) => {}
                                }
                                Line::Signing { index, pq, held: h.held.len(), deferred: h.deferred.len() }
                            }
                        }
                    }
                }
            }
        };
        lines.push((p.origin.clone(), line));
    }
    Report {
        registered: guardians.len(),
        quorum: quorum(guardians.len()),
        lines,
        missing: (0..guardians.len()).filter(|i| !seen.contains_key(i)).collect(),
        signing,
        pq: (!pq_guardians.is_empty()).then(|| PqReport {
            registered: pq_guardians.len(),
            quorum: quorum(pq_guardians.len()),
            signing: pq_signing,
            unknown: pq_unknown,
        }),
    }
}

/// The report as text.
pub fn render(r: &Report, min_spare: i64) -> String {
    let mut out = format!("registered guardians: {}; signatures required: {}\n", r.registered, r.quorum);
    for (origin, line) in &r.lines {
        let text = match line {
            Line::Signing { index, pq, held, deferred } => format!(
                "guardian {index}: signing; PQ key {}{}",
                match pq {
                    Some(true) => "registered",
                    Some(false) => "NOT the registered one (its co-signatures do not count)",
                    None => "not reported by this build",
                },
                if *held + *deferred > 0 { format!("; {held} held, {deferred} deferred") } else { String::new() }
            ),
            Line::Paused { index, reason } => format!("guardian {index}: PAUSED ({reason})"),
            Line::NotRegistered { guardian } => format!("answers as 0x{guardian}, which is not in the registered set"),
            Line::Duplicate { index } => format!("guardian {index} again (counted once)"),
            Line::Down { error } => format!("DOWN: {error}"),
        };
        out.push_str(&format!("  {origin:<28} {text}\n"));
    }
    if !r.missing.is_empty() {
        let list: Vec<String> = r.missing.iter().map(|i| i.to_string()).collect();
        out.push_str(&format!("  no origin answered as registered guardian(s) {}\n", list.join(", ")));
    }
    let word = |spare: i64| match spare {
        s if s < 0 => format!("BELOW QUORUM by {}: nothing is signed", -s),
        0 => "NO SPARE: any one guardian stopping stops it".to_string(),
        s => format!("{s} spare"),
    };
    out.push_str(&format!("releases: {} of {} required are signing; {}\n", r.signing, r.quorum, word(r.spare())));
    if let Some(p) = &r.pq {
        out.push_str(&format!(
            "mints: {} of {} required PQ co-signers are signing{}; {}\n",
            p.signing,
            p.quorum,
            if p.unknown > 0 { format!(" ({} more unknown, not counted)", p.unknown) } else { String::new() },
            word(p.signing as i64 - p.quorum as i64)
        ));
    }
    out.push_str(&format!(
        "{}: at least {min_spare} spare is asked for (BR-402)\n",
        if r.ok(min_spare) { "OK" } else { "ALERT" }
    ));
    out
}
