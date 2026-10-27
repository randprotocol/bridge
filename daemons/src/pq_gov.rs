//! The Rand-only governance messages (`spec/PQ-COSIGNATURE.md` §8): fixed
//! big-endian layouts that an auditor or a hardware signer can reproduce by
//! hand. None of them ever reaches a source-chain endpoint.
//!
//! Two binding forms (BRG-901). A chain cut without `binding_domain` in its
//! genesis (chains 14–19) verifies the §8 layouts, which bind the chain id
//! alone. A chain cut with `binding_domain: 1` (chain 20 onward) verifies the
//! genesis-bound form: the same message with the tag's version digit bumped
//! to `2` and the 32-byte genesis hash between the tag and the chain id —
//! `tag_v2 ‖ genesis [32] ‖ chain_id u64 ‖ nonce u64 ‖ tail` — so a pause or a
//! quorum signed for one chain verifies on no re-cut sharing its id. The
//! `*_message_in` functions build either from a [`BindingDomain`], byte for
//! byte what the fullnode verifies (`crates/randprotocol-core/src/bridge/gov.rs`).
//! Which form a chain takes is decided by its chain id, never by what a node
//! claims ([`binding_domain_for`]).

use anyhow::{bail, Result};

use crate::pq::{self, PqKey, PqSignature};

pub const DOMAIN_PAUSE: &[u8] = b"rand-bridge-pause-1";
pub const DOMAIN_UNPAUSE: &[u8] = b"rand-bridge-pq-unpause-1";
pub const DOMAIN_LIST: &[u8] = b"rand-bridge-pq-list-1";
pub const DOMAIN_REGISTER: &[u8] = b"rand-bridge-pq-register-1";

/// The rotations of the PQ guardian set and of the pause key (BRG-14), as
/// the fullnode builds them (`bridge/gov.rs` `rotate_pq_message`,
/// `rotate_pause_message`, `cancel_rotation_message`; its `docs/bridge.md`
/// §21): signed by a PQ quorum of the current set at `rotation_nonce`; with
/// `bridge.rotation.needs_possession`, also by each new key.
pub const DOMAIN_ROTATE_PQ: &[u8] = b"rand-bridge-pq-rotate-pq-1";
pub const DOMAIN_ROTATE_PAUSE: &[u8] = b"rand-bridge-pq-rotate-pause-1";
/// Signed by the current pause key to drop a pending (delayed) rotation.
pub const DOMAIN_CANCEL_ROTATION: &[u8] = b"rand-bridge-cancel-rotation-1";
pub const DOMAIN_ROTATE_PQ_V2: &[u8] = b"rand-bridge-pq-rotate-pq-2";
pub const DOMAIN_ROTATE_PAUSE_V2: &[u8] = b"rand-bridge-pq-rotate-pause-2";
pub const DOMAIN_CANCEL_ROTATION_V2: &[u8] = b"rand-bridge-cancel-rotation-2";

/// The genesis-bound tags: the §8 tags with their version digit at `2`.
pub const DOMAIN_PAUSE_V2: &[u8] = b"rand-bridge-pause-2";
pub const DOMAIN_UNPAUSE_V2: &[u8] = b"rand-bridge-pq-unpause-2";
pub const DOMAIN_LIST_V2: &[u8] = b"rand-bridge-pq-list-2";
pub const DOMAIN_REGISTER_V2: &[u8] = b"rand-bridge-pq-register-2";

/// The chain ids of every public Rand chain whose genesis carries no
/// `binding_domain`: chains 14–19. On these, and only these, a governance
/// message binds the chain id alone. Every later chain binds its genesis hash.
/// Mirrors the fullnode's `randprotocol_client::CHAIN_ID_BINDING_CHAIN_IDS`.
pub const CHAIN_ID_BINDING_CHAIN_IDS: &[u64] = &[14, 15, 16, 17, 18, 19];

/// What a governance message binds besides its chain id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingDomain {
    /// A chain cut without `binding_domain`: the §8 layouts.
    ChainId,
    /// A chain cut with `binding_domain: 1`: this genesis hash, under the `…-2` tags.
    Genesis([u8; 32]),
}

impl BindingDomain {
    /// One line for a signer's output: which form, and which genesis if any.
    pub fn describe(&self) -> String {
        match self {
            BindingDomain::ChainId => "chain id only (the `…-1` layouts, chains 14-19)".into(),
            BindingDomain::Genesis(g) => {
                format!("genesis {} (the `…-2` layouts)", hex::encode(g))
            }
        }
    }
}

/// The binding a message for `rand_chain_id` takes, given the chain's genesis
/// hash when the caller has one. Decided by the chain id: a chain in
/// [`CHAIN_ID_BINDING_CHAIN_IDS`] takes the chain-id form and refuses a
/// genesis (the real chain with that id accepts nothing else); every other
/// chain needs its genesis hash and takes the genesis-bound form.
pub fn binding_domain_for(rand_chain_id: u64, genesis: Option<[u8; 32]>) -> Result<BindingDomain> {
    if CHAIN_ID_BINDING_CHAIN_IDS.contains(&rand_chain_id) {
        if genesis.is_some() {
            bail!(
                "Rand chain {rand_chain_id} was cut without binding_domain and signs the chain-id \
                 form: drop the genesis hash"
            );
        }
        return Ok(BindingDomain::ChainId);
    }
    match genesis {
        Some(g) => Ok(BindingDomain::Genesis(g)),
        None => bail!(
            "Rand chain {rand_chain_id} binds its genesis hash (binding_domain 1): pass the \
             32-byte genesis hash (--genesis <hex>, or --rand-rpc <url> to read \
             rand_getGenesisHash)"
        ),
    }
}

/// `v1` as it stands under [`BindingDomain::ChainId`]; under `Genesis`, `v1`
/// with its tag (`tag`, a prefix of it) replaced by `tag_v2 ‖ genesis`.
fn rebind(domain: &BindingDomain, tag: &[u8], tag_v2: &[u8], v1: Vec<u8>) -> Vec<u8> {
    match domain {
        BindingDomain::ChainId => v1,
        BindingDomain::Genesis(genesis) => {
            let mut m = Vec::with_capacity(tag_v2.len() + 32 + v1.len() - tag.len());
            m.extend_from_slice(tag_v2);
            m.extend_from_slice(genesis);
            m.extend_from_slice(&v1[tag.len()..]);
            m
        }
    }
}

fn head(domain: &[u8], rand_chain_id: u64, nonce: u64) -> Vec<u8> {
    let mut m = domain.to_vec();
    m.extend_from_slice(&rand_chain_id.to_be_bytes());
    m.extend_from_slice(&nonce.to_be_bytes());
    m
}

/// Signed by the one genesis pause key. It can pause minting, never unpause.
pub fn pause_message(rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    head(DOMAIN_PAUSE, rand_chain_id, pause_nonce)
}

/// [`pause_message`] on a chain of `domain`.
pub fn pause_message_in(domain: &BindingDomain, rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    rebind(
        domain,
        DOMAIN_PAUSE,
        DOMAIN_PAUSE_V2,
        pause_message(rand_chain_id, pause_nonce),
    )
}

/// Signed by a PQ guardian quorum.
pub fn unpause_message(rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    head(DOMAIN_UNPAUSE, rand_chain_id, pause_nonce)
}

/// [`unpause_message`] on a chain of `domain`.
pub fn unpause_message_in(domain: &BindingDomain, rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    rebind(
        domain,
        DOMAIN_UNPAUSE,
        DOMAIN_UNPAUSE_V2,
        unpause_message(rand_chain_id, pause_nonce),
    )
}

/// One backing: a coin on a source chain, as the endpoint names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backing {
    /// Bridge chain id, 2..=5.
    pub chain: u16,
    /// The 32-byte wire form of the token (`docs/architecture.md` §10.1).
    pub token: [u8; 32],
    /// The coin's decimals on its own chain.
    pub decimals: u8,
}

fn backing_tail(m: &mut Vec<u8>, b: &Backing) {
    m.extend_from_slice(&b.chain.to_be_bytes());
    m.extend_from_slice(&b.token);
    m.push(b.decimals);
}

/// `ListBacking`: add `backing` to the bridged token at `token_index`.
pub fn list_message(
    rand_chain_id: u64,
    list_nonce: u64,
    token_index: u32,
    backing: &Backing,
) -> Vec<u8> {
    let mut m = head(DOMAIN_LIST, rand_chain_id, list_nonce);
    m.extend_from_slice(&token_index.to_be_bytes());
    backing_tail(&mut m, backing);
    m
}

/// [`list_message`] on a chain of `domain`.
pub fn list_message_in(
    domain: &BindingDomain,
    rand_chain_id: u64,
    list_nonce: u64,
    token_index: u32,
    backing: &Backing,
) -> Vec<u8> {
    rebind(
        domain,
        DOMAIN_LIST,
        DOMAIN_LIST_V2,
        list_message(rand_chain_id, list_nonce, token_index, backing),
    )
}

/// `RegisterBridgedToken`: a new bridged token with its first backing.
pub fn register_message(
    rand_chain_id: u64,
    list_nonce: u64,
    name: &str,
    symbol: &str,
    salt: &[u8; 32],
    backing: &Backing,
) -> Result<Vec<u8>> {
    if name.is_empty() || name.len() > 255 || symbol.is_empty() || symbol.len() > 255 {
        bail!("name and symbol are 1..=255 bytes (a u8 length prefix)");
    }
    let mut m = head(DOMAIN_REGISTER, rand_chain_id, list_nonce);
    m.push(name.len() as u8);
    m.extend_from_slice(name.as_bytes());
    m.push(symbol.len() as u8);
    m.extend_from_slice(symbol.as_bytes());
    m.extend_from_slice(salt);
    backing_tail(&mut m, backing);
    Ok(m)
}

/// [`register_message`] on a chain of `domain`.
pub fn register_message_in(
    domain: &BindingDomain,
    rand_chain_id: u64,
    list_nonce: u64,
    name: &str,
    symbol: &str,
    salt: &[u8; 32],
    backing: &Backing,
) -> Result<Vec<u8>> {
    let v1 = register_message(rand_chain_id, list_nonce, name, symbol, salt, backing)?;
    Ok(rebind(domain, DOMAIN_REGISTER, DOMAIN_REGISTER_V2, v1))
}

fn check_pq_key(what: &str, key: &[u8]) -> Result<()> {
    if key.len() != pq::PUBLIC_KEY_LEN {
        bail!(
            "{what} is {} bytes, a Dilithium2 public key is {}",
            key.len(),
            pq::PUBLIC_KEY_LEN
        );
    }
    Ok(())
}

/// `M_rotate_pq`: `tag ‖ chain_id ‖ rotation_nonce ‖ u32 count ‖ key [1312] …`,
/// the new set in index order.
pub fn rotate_pq_message(
    rand_chain_id: u64,
    rotation_nonce: u64,
    new_pq_guardians: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if new_pq_guardians.is_empty() {
        bail!("a PQ guardian set needs at least one key");
    }
    let mut m = head(DOMAIN_ROTATE_PQ, rand_chain_id, rotation_nonce);
    m.extend_from_slice(&(new_pq_guardians.len() as u32).to_be_bytes());
    for (i, k) in new_pq_guardians.iter().enumerate() {
        check_pq_key(&format!("new PQ guardian {i}"), k)?;
        if new_pq_guardians[..i].contains(k) {
            bail!("new PQ guardian {i} repeats an earlier key");
        }
        m.extend_from_slice(k);
    }
    Ok(m)
}

/// [`rotate_pq_message`] on a chain of `domain`.
pub fn rotate_pq_message_in(
    domain: &BindingDomain,
    rand_chain_id: u64,
    rotation_nonce: u64,
    new_pq_guardians: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let v1 = rotate_pq_message(rand_chain_id, rotation_nonce, new_pq_guardians)?;
    Ok(rebind(domain, DOMAIN_ROTATE_PQ, DOMAIN_ROTATE_PQ_V2, v1))
}

/// `M_rotate_pause`: `tag ‖ chain_id ‖ rotation_nonce ‖ key [1312]`.
pub fn rotate_pause_message(
    rand_chain_id: u64,
    rotation_nonce: u64,
    new_pause_key: &[u8],
) -> Result<Vec<u8>> {
    check_pq_key("the new pause key", new_pause_key)?;
    let mut m = head(DOMAIN_ROTATE_PAUSE, rand_chain_id, rotation_nonce);
    m.extend_from_slice(new_pause_key);
    Ok(m)
}

/// [`rotate_pause_message`] on a chain of `domain`.
pub fn rotate_pause_message_in(
    domain: &BindingDomain,
    rand_chain_id: u64,
    rotation_nonce: u64,
    new_pause_key: &[u8],
) -> Result<Vec<u8>> {
    let v1 = rotate_pause_message(rand_chain_id, rotation_nonce, new_pause_key)?;
    Ok(rebind(domain, DOMAIN_ROTATE_PAUSE, DOMAIN_ROTATE_PAUSE_V2, v1))
}

/// Which pending rotation a cancel drops: the fullnode's `RotationKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationKind {
    PqGuardians = 0,
    PauseKey = 1,
}

/// `M_cancel`: `tag ‖ chain_id ‖ rotation_nonce ‖ kind u8`, signed by the
/// current pause key.
pub fn cancel_rotation_message(rand_chain_id: u64, rotation_nonce: u64, kind: RotationKind) -> Vec<u8> {
    let mut m = head(DOMAIN_CANCEL_ROTATION, rand_chain_id, rotation_nonce);
    m.push(kind as u8);
    m
}

/// [`cancel_rotation_message`] on a chain of `domain`.
pub fn cancel_rotation_message_in(
    domain: &BindingDomain,
    rand_chain_id: u64,
    rotation_nonce: u64,
    kind: RotationKind,
) -> Vec<u8> {
    rebind(
        domain,
        DOMAIN_CANCEL_ROTATION,
        DOMAIN_CANCEL_ROTATION_V2,
        cancel_rotation_message(rand_chain_id, rotation_nonce, kind),
    )
}

/// `index:signature-hex` lines, what `rand-node bridge-gov … submit` reads
/// (`#` comments and blank lines ignored). Refuses a repeated index and
/// returns them in index order.
pub fn parse_signature_lines(text: &str) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    for raw in text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .flat_map(|l| l.split_whitespace())
    {
        let (index, sig) = raw
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("expected index:signature-hex"))?;
        let index: u8 = index
            .parse()
            .map_err(|_| anyhow::anyhow!("{index:?} is not a signer index"))?;
        let sig = hex::decode(sig.trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("signer {index}'s signature is not hex"))?;
        if out.iter().any(|(i, _)| *i == index) {
            bail!("signer index {index} appears twice");
        }
        out.push((index, sig));
    }
    out.sort_by_key(|(i, _)| *i);
    Ok(out)
}

/// One `index:signature-hex` line.
pub fn signature_line(index: u8, signature: &[u8]) -> String {
    format!("{index}:{}", hex::encode(signature))
}

/// The quorum lines as the ledger will judge them: exactly the rules of
/// [`pq::check_raw`] over `message` under the current set.
pub fn check_quorum_lines(
    lines: &[(u8, Vec<u8>)],
    pq_guardians: &[Vec<u8>],
    message: &[u8],
) -> Result<()> {
    let list: Vec<PqSignature> = lines
        .iter()
        .map(|(index, s)| PqSignature {
            index: *index,
            signature: hex::encode(s),
        })
        .collect();
    pq::check_raw(&list, pq_guardians, message)
        .map_err(|e| anyhow::anyhow!("the quorum would be refused: {e:?}"))
}

/// The possession lines: exactly one per new key, indices `0..n`, each new
/// key's own signature over the rotation message.
pub fn check_possession_lines(
    lines: &[(u8, Vec<u8>)],
    new_keys: &[Vec<u8>],
    message: &[u8],
) -> Result<()> {
    if lines.len() != new_keys.len()
        || lines.iter().enumerate().any(|(i, (index, _))| usize::from(*index) != i)
    {
        bail!(
            "possession lines must be exactly one per new key, indices 0..{} (got {:?})",
            new_keys.len(),
            lines.iter().map(|(i, _)| *i).collect::<Vec<_>>()
        );
    }
    for (key, (index, sig)) in new_keys.iter().zip(lines) {
        if !pq::verify_raw(key, message, sig) {
            bail!("possession signature {index} does not verify under new key {index}");
        }
    }
    Ok(())
}

/// A PQ guardian quorum over an arbitrary governance message: each seed is
/// matched to `pq_guardians` by public key, exactly a quorum is kept (lowest
/// indices first) and the result is checked under the ledger's five rules.
pub fn sign_quorum(
    message: &[u8],
    pq_guardians: &[Vec<u8>],
    signers: &[PqKey],
) -> Result<Vec<PqSignature>> {
    let mut found = Vec::new();
    for key in signers {
        let Some(index) = pq_guardians.iter().position(|k| *k == key.public_key()) else {
            bail!("a signer's key is not in pq_guardians");
        };
        found.push((index as u8, key.sign_raw(message)));
    }
    let Some(quorum) = pq::assemble_raw(&found, pq_guardians, message) else {
        bail!(
            "{} signers, but {} keys need {}",
            found.len(),
            pq_guardians.len(),
            pq::quorum(pq_guardians.len())
        );
    };
    if let Err(e) = pq::check_raw(&quorum, pq_guardians, message) {
        bail!("self-check failed: {e:?}");
    }
    Ok(quorum)
}
