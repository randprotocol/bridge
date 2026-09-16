//! Builds every test-vector case. Each `case_*` function returns one
//! [`Vector`]; [`build`] assembles the full [`VectorsFile`].
//!
//! Guardian secrets are `[0u8; 31] ++ [i]` for `i = 1..=6`, plus a 7th
//! (`[0u8; 31] ++ [7]`) used only for the guardian-set-upgrade cases.
//! "Guardian N" below always means the 1-based secret `secrets[N - 1]`
//! unless a comment says otherwise.

use randprotocol_core::bridge as b;

use crate::types::{BodyJson, GuardianEntry, PayloadJson, SetEntry, Vector, VectorsFile};

const NOW: u64 = 1_800_000_000;
const TIMESTAMP: u32 = 1_799_999_000;

/// Shared fixtures: guardian secrets/addresses, emitters, token addresses.
struct Ctx {
    secrets: [[u8; 32]; 6],
    addrs: [[u8; 20]; 6],
    addr7: [u8; 20],
    addr8: [u8; 20],
    emitters: [[u8; 32]; 4], // index 0 => chain 2, .. index 3 => chain 5
    rand_emitter: [u8; 32],
    governance_emitter: [u8; 32],
}

impl Ctx {
    fn new() -> Self {
        let mut secrets = [[0u8; 32]; 6];
        for (i, s) in secrets.iter_mut().enumerate() {
            s[31] = (i + 1) as u8;
        }
        let mut secret7 = [0u8; 32];
        secret7[31] = 7;
        let mut secret8 = [0u8; 32];
        secret8[31] = 8;

        let addrs = secrets.map(|s| b::guardian_address(&s));
        let addr7 = b::guardian_address(&secret7);
        let addr8 = b::guardian_address(&secret8);

        // Source-chain emitters: EVM chains (2 Ethereum, 3 BSC, 4 Tron) are
        // contract addresses, so left-pad to the same 12-zero ++ 20-byte
        // convention as `evm_token_addr`/`evm_to`; Solana (5) keeps the
        // full 32-byte hash.
        let emitters = [2u16, 3, 4, 5].map(|chain| {
            let hash = b::keccak256(format!("emitter-{chain}").as_bytes());
            if chain == 5 {
                hash
            } else {
                let mut out = [0u8; 32];
                out[12..32].copy_from_slice(&hash[12..32]);
                out
            }
        });
        let rand_emitter = b::keccak256(b"rand-bridge-emitter-test");
        let governance_emitter = b::GOVERNANCE_EMITTER;

        Ctx {
            secrets,
            addrs,
            addr7,
            addr8,
            emitters,
            rand_emitter,
            governance_emitter,
        }
    }

    fn emitter(&self, chain: u16) -> [u8; 32] {
        self.emitters[(chain - 2) as usize]
    }

    /// The 6 keys of "set 1": guardians 2..=6 plus the 7th secret, in that
    /// order (used by `upgrade_set1_ok` and every `..._set1_*` case).
    fn set1_addrs(&self) -> [[u8; 20]; 6] {
        [
            self.addrs[1],
            self.addrs[2],
            self.addrs[3],
            self.addrs[4],
            self.addrs[5],
            self.addr7,
        ]
    }
}

fn hex32(x: &[u8; 32]) -> String {
    hex::encode(x)
}

fn hex20(x: &[u8; 20]) -> String {
    hex::encode(x)
}

/// A 32-byte "native" token identifier (used only for Solana, chain 5,
/// where the token address really is a 32-byte mint pubkey).
fn token_addr(label: &str) -> [u8; 32] {
    b::keccak256(label.as_bytes())
}

/// A left-padded 20-byte EVM address (12 zero bytes ++ 20 address bytes),
/// per spec 3.5: `token_address`/`emitter_address` for the EVM-family
/// chains (2 Ethereum, 3 BSC, 4 Tron) are real 20-byte contract addresses
/// widened into the wire format's 32-byte field, the same left-padding
/// convention already used for the `to` field on EVM releases (see
/// `evm_to`). Solana (chain 5) keeps the full 32-byte value via
/// `token_addr` instead, since its addresses/mints are natively 32 bytes.
fn evm_token_addr(label: &str) -> [u8; 32] {
    let hash = b::keccak256(label.as_bytes());
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&hash[12..32]);
    out
}

/// Decimal string of a big-endian u256 (`amount`/`fee` on the wire), via
/// repeated base-256 -> base-10 long division. No bignum dependency needed
/// for 32 bytes.
fn big_dec(bytes: &[u8; 32]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        return "0".to_string();
    }
    let mut digits = bytes.to_vec();
    let mut out = Vec::new();
    loop {
        let mut rem: u32 = 0;
        let mut any_nonzero = false;
        for d in digits.iter_mut() {
            let cur = (rem << 8) | (*d as u32);
            *d = (cur / 10) as u8;
            rem = cur % 10;
            if *d != 0 {
                any_nonzero = true;
            }
        }
        out.push(b'0' + rem as u8);
        if !any_nonzero {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

fn u256(v: u128) -> [u8; 32] {
    b::Transfer::u256_from_u128(v)
}

fn evm_to() -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(&[0x22u8; 20]);
    t
}

fn sol_to() -> [u8; 32] {
    [0x22u8; 32]
}

const RECIPIENT: [u8; 32] = [0x11u8; 32];

fn default_set(ctx: &Ctx) -> Vec<SetEntry> {
    vec![SetEntry {
        index: 0,
        keys: ctx.addrs.iter().map(hex20).collect(),
        expires_at: 0,
    }]
}

/// `secp256k1` curve order `n`, big-endian.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41,
];

/// `n - s`, both 32-byte big-endian.
fn sub_from_n(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let a = SECP256K1_N[i] as i32;
        let b = s[i] as i32 + borrow;
        if a < b {
            out[i] = (a + 256 - b) as u8;
            borrow = 1;
        } else {
            out[i] = (a - b) as u8;
            borrow = 0;
        }
    }
    out
}

fn transfer_payload_json(
    amount: &[u8; 32],
    token_address: &[u8; 32],
    token_chain: u16,
    to: &[u8; 32],
    to_chain: u16,
    fee: &[u8; 32],
) -> PayloadJson {
    PayloadJson::Transfer {
        id: 1,
        amount: big_dec(amount),
        token_address: hex32(token_address),
        token_chain,
        to: hex32(to),
        to_chain,
        fee: big_dec(fee),
    }
}

fn body_json(nonce: u32, emitter_chain: u16, emitter_address: &[u8; 32], sequence: u64) -> BodyJson {
    body_json_at(nonce, emitter_chain, emitter_address, sequence, 1)
}

/// [`body_json`] with an explicit `consistency_level`. Governance
/// (payload id 2) messages carry 0 per spec 3.6, everything else here
/// carries 1.
fn body_json_at(
    nonce: u32,
    emitter_chain: u16,
    emitter_address: &[u8; 32],
    sequence: u64,
    consistency_level: u8,
) -> BodyJson {
    BodyJson {
        timestamp: TIMESTAMP,
        nonce,
        emitter_chain,
        emitter_address: hex32(emitter_address),
        sequence,
        consistency_level,
    }
}

/// Encodes the envelope, computes `mu`, and assembles the [`Vector`].
/// `version_override`, when set, overwrites byte 0 of the encoded
/// attestation *after* signing (so signatures stay valid over the body).
#[allow(clippy::too_many_arguments)]
fn finish(
    name: &str,
    verifier_chain: u16,
    guardian_set_index: u32,
    sets: Vec<SetEntry>,
    current_set: u32,
    expect: &str,
    body: b::Body,
    body_json: BodyJson,
    payload_json: PayloadJson,
    signatures: Vec<b::Signature>,
    version_override: Option<u8>,
) -> Vector {
    let digest = b::digest(&body.encode());
    let att = b::Attestation {
        guardian_set_index,
        signatures,
        body,
    };
    let mut bytes = att.encode();
    if let Some(v) = version_override {
        bytes[0] = v;
    }
    Vector {
        name: name.to_string(),
        attestation: hex::encode(&bytes),
        digest: hex::encode(digest),
        verifier_chain,
        guardian_set_index,
        sets,
        current_set,
        expect: expect.to_string(),
        body: body_json,
        payload: payload_json,
        replay_of: None,
    }
}

/// Standard signer set: guardians 1..=5 (secrets[0..5]) as indices 0..=4,
/// the 5-of-6 quorum used by every "normal" case.
fn sign_std(ctx: &Ctx, digest: &[u8; 32]) -> Vec<b::Signature> {
    (0..5)
        .map(|i| b::sign_digest(&ctx.secrets[i], i as u8, digest))
        .collect()
}

/// Signer set for "set 1": guardians 2..=6 (secrets[1..6]) as indices
/// 0..=4, matching `Ctx::set1_addrs`'s first 5 keys.
fn sign_set1(ctx: &Ctx, digest: &[u8; 32]) -> Vec<b::Signature> {
    (0..5)
        .map(|i| b::sign_digest(&ctx.secrets[i + 1], i as u8, digest))
        .collect()
}

pub fn build() -> VectorsFile {
    let ctx = Ctx::new();
    let mut vectors = Vec::new();

    // -- transfer_eth_usdt_6dp_ok ------------------------------------
    let eth_amount = u256(100_000_000);
    let eth_fee = u256(1_000);
    let eth_token = evm_token_addr("usdt-2");
    let eth_body = b::Body {
        timestamp: TIMESTAMP,
        nonce: 7,
        emitter_chain: 2,
        emitter_address: ctx.emitter(2),
        sequence: 3,
        consistency_level: 1,
        payload: b::Payload::Transfer(b::Transfer {
            amount: eth_amount,
            token_address: eth_token,
            token_chain: 2,
            to: RECIPIENT,
            to_chain: 1,
            fee: eth_fee,
        })
        .encode(),
    };
    let eth_digest = b::digest(&eth_body.encode());
    let eth_sigs = sign_std(&ctx, &eth_digest);
    let eth_vector = finish(
        "transfer_eth_usdt_6dp_ok",
        1,
        0,
        default_set(&ctx),
        0,
        "ok",
        eth_body,
        body_json(7, 2, &ctx.emitter(2), 3),
        transfer_payload_json(&eth_amount, &eth_token, 2, &RECIPIENT, 1, &eth_fee),
        eth_sigs,
        None,
    );
    // Keep the exact bytes/digest around for `replay_eth`.
    let eth_attestation_hex = eth_vector.attestation.clone();
    let eth_digest_hex = eth_vector.digest.clone();
    vectors.push(eth_vector);

    // -- transfer_bsc_usdt_18dp_ok ------------------------------------
    {
        let amount = u256(250_000_000_000);
        let fee = u256(0);
        let token = evm_token_addr("usdt-3");
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 3,
            emitter_address: ctx.emitter(3),
            sequence: 4,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 3,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "transfer_bsc_usdt_18dp_ok",
            1,
            0,
            default_set(&ctx),
            0,
            "ok",
            body,
            body_json(7, 3, &ctx.emitter(3), 4),
            transfer_payload_json(&amount, &token, 3, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- transfer_tron_usdt_ok -----------------------------------------
    {
        let amount = u256(500_000_000);
        let fee = u256(5);
        let token = evm_token_addr("usdt-4");
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 4,
            emitter_address: ctx.emitter(4),
            sequence: 5,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 4,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "transfer_tron_usdt_ok",
            1,
            0,
            default_set(&ctx),
            0,
            "ok",
            body,
            body_json(7, 4, &ctx.emitter(4), 5),
            transfer_payload_json(&amount, &token, 4, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- transfer_sol_usdc_ok --------------------------------------------
    {
        let amount = u256(12_345_678);
        let fee = u256(0);
        let token = token_addr("usdc-5");
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 5,
            emitter_address: ctx.emitter(5),
            sequence: 6,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 5,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "transfer_sol_usdc_ok",
            1,
            0,
            default_set(&ctx),
            0,
            "ok",
            body,
            body_json(7, 5, &ctx.emitter(5), 6),
            transfer_payload_json(&amount, &token, 5, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- release_to_{eth,bsc,tron}_ok (EVM) + release_to_sol_ok ----------
    let release_amount = u256(100_000_000);
    let release_fee = u256(1_000);
    for (i, (name, chain)) in [
        ("release_to_eth_ok", 2u16),
        ("release_to_bsc_ok", 3u16),
        ("release_to_tron_ok", 4u16),
    ]
    .into_iter()
    .enumerate()
    {
        let token = evm_token_addr(&format!("usdt-{chain}"));
        let to = evm_to();
        let sequence = i as u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: ctx.rand_emitter,
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount: release_amount,
                token_address: token,
                token_chain: chain,
                to,
                to_chain: chain,
                fee: release_fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            name,
            chain,
            0,
            default_set(&ctx),
            0,
            "ok",
            body,
            body_json(0, 1, &ctx.rand_emitter, sequence),
            transfer_payload_json(&release_amount, &token, chain, &to, chain, &release_fee),
            sigs,
            None,
        ));
    }
    {
        let token = token_addr("usdt-5");
        let to = sol_to();
        let sequence = 3u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: ctx.rand_emitter,
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount: release_amount,
                token_address: token,
                token_chain: 5,
                to,
                to_chain: 5,
                fee: release_fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "release_to_sol_ok",
            5,
            0,
            default_set(&ctx),
            0,
            "ok",
            body,
            body_json(0, 1, &ctx.rand_emitter, sequence),
            transfer_payload_json(&release_amount, &token, 5, &to, 5, &release_fee),
            sigs,
            None,
        ));
    }

    // -- upgrade_set1_ok --------------------------------------------------
    // Governance messages carry `consistency_level = 0` (spec 3.6).
    {
        let new_keys = ctx.set1_addrs();
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: ctx.governance_emitter,
            sequence: 1,
            consistency_level: 0,
            payload: b::Payload::GuardianSetUpgrade(b::GuardianSetUpgrade {
                new_index: 1,
                keys: new_keys.to_vec(),
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "upgrade_set1_ok",
            1,
            0,
            default_set(&ctx),
            0,
            "ok",
            body,
            body_json_at(0, 1, &ctx.governance_emitter, 1, 0),
            PayloadJson::Upgrade {
                id: 2,
                new_index: 1,
                keys: new_keys.iter().map(hex20).collect(),
            },
            sigs,
            None,
        ));
    }

    // -- upgrade_signed_by_superseded_set ---------------------------------
    // Set 1 is current; set 0 has been superseded but is still inside its
    // 86400 s grace window, which spec 3.4/3.6 scopes to transfer payloads.
    // A payload-2 rotation additionally requires
    // `guardian_set_index == current`, so this one must be refused even
    // though the very same signatures would still mint a transfer.
    {
        let new_keys: [[u8; 20]; 6] = [
            ctx.addrs[2],
            ctx.addrs[3],
            ctx.addrs[4],
            ctx.addrs[5],
            ctx.addr7,
            ctx.addr8,
        ];
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: ctx.governance_emitter,
            sequence: 2,
            consistency_level: 0,
            payload: b::Payload::GuardianSetUpgrade(b::GuardianSetUpgrade {
                new_index: 2,
                keys: new_keys.to_vec(),
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        let sets = vec![
            SetEntry {
                index: 0,
                keys: ctx.addrs.iter().map(hex20).collect(),
                expires_at: NOW + 100,
            },
            SetEntry {
                index: 1,
                keys: ctx.set1_addrs().iter().map(hex20).collect(),
                expires_at: 0,
            },
        ];
        vectors.push(finish(
            "upgrade_signed_by_superseded_set",
            1,
            0,
            sets,
            1,
            "stale_governance_set",
            body,
            body_json_at(0, 1, &ctx.governance_emitter, 2, 0),
            PayloadJson::Upgrade {
                id: 2,
                new_index: 2,
                keys: new_keys.iter().map(hex20).collect(),
            },
            sigs,
            None,
        ));
    }

    // Two-set fixture shared by the next three cases: set 0 (original 6
    // guardians) and set 1 (guardians 2..=6 + the 7th secret).
    let set1_entry = |expires_at: u64| SetEntry {
        index: 1,
        keys: ctx.set1_addrs().iter().map(hex20).collect(),
        expires_at,
    };

    // -- transfer_signed_by_set1_ok ---------------------------------------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 100u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_set1(&ctx, &digest);
        let sets = vec![
            SetEntry {
                index: 0,
                keys: ctx.addrs.iter().map(hex20).collect(),
                expires_at: NOW - 1,
            },
            set1_entry(0),
        ];
        vectors.push(finish(
            "transfer_signed_by_set1_ok",
            1,
            1,
            sets,
            1,
            "ok",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- transfer_old_set_in_grace_ok / transfer_old_set_expired -----------
    for (name, set0_expires_at, expect) in [
        ("transfer_old_set_in_grace_ok", NOW + 100, "ok"),
        ("transfer_old_set_expired", NOW - 1, "set_expired"),
    ] {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = if name == "transfer_old_set_in_grace_ok" {
            101u64
        } else {
            102u64
        };
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        let sets = vec![
            SetEntry {
                index: 0,
                keys: ctx.addrs.iter().map(hex20).collect(),
                expires_at: set0_expires_at,
            },
            set1_entry(0),
        ];
        vectors.push(finish(
            name,
            1,
            0,
            sets,
            1,
            expect,
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- transfer_unknown_set ------------------------------------------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 103u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "transfer_unknown_set",
            1,
            5,
            default_set(&ctx),
            0,
            "unknown_set",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- quorum_four / quorum_five_ok / quorum_six_ok -----------------------
    for (name, n_sigs, sequence, expect) in [
        ("quorum_four", 4usize, 104u64, "no_quorum"),
        ("quorum_five_ok", 5usize, 105u64, "ok"),
        ("quorum_six_ok", 6usize, 106u64, "ok"),
    ] {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs: Vec<b::Signature> = (0..n_sigs)
            .map(|i| b::sign_digest(&ctx.secrets[i], i as u8, &digest))
            .collect();
        vectors.push(finish(
            name,
            1,
            0,
            default_set(&ctx),
            0,
            expect,
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- dup_index / decreasing_index / index_six ---------------------------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");

        // dup_index: indices [0,1,2,3,3]
        {
            let sequence = 107u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 2,
                emitter_address: ctx.emitter(2),
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sig3 = b::sign_digest(&ctx.secrets[3], 3, &digest);
            let sigs = vec![
                b::sign_digest(&ctx.secrets[0], 0, &digest),
                b::sign_digest(&ctx.secrets[1], 1, &digest),
                b::sign_digest(&ctx.secrets[2], 2, &digest),
                sig3.clone(),
                sig3,
            ];
            vectors.push(finish(
                "dup_index",
                1,
                0,
                default_set(&ctx),
                0,
                "index_order",
                body,
                body_json(7, 2, &ctx.emitter(2), sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }

        // decreasing_index: indices [0,1,2,4,3]
        {
            let sequence = 108u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 2,
                emitter_address: ctx.emitter(2),
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sigs = vec![
                b::sign_digest(&ctx.secrets[0], 0, &digest),
                b::sign_digest(&ctx.secrets[1], 1, &digest),
                b::sign_digest(&ctx.secrets[2], 2, &digest),
                b::sign_digest(&ctx.secrets[4], 4, &digest),
                b::sign_digest(&ctx.secrets[3], 3, &digest),
            ];
            vectors.push(finish(
                "decreasing_index",
                1,
                0,
                default_set(&ctx),
                0,
                "index_order",
                body,
                body_json(7, 2, &ctx.emitter(2), sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }

        // index_six: indices [0,1,2,3] + guardian 5's signature relabelled 6
        {
            let sequence = 109u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 2,
                emitter_address: ctx.emitter(2),
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sigs = vec![
                b::sign_digest(&ctx.secrets[0], 0, &digest),
                b::sign_digest(&ctx.secrets[1], 1, &digest),
                b::sign_digest(&ctx.secrets[2], 2, &digest),
                b::sign_digest(&ctx.secrets[3], 3, &digest),
                b::sign_digest(&ctx.secrets[4], 6, &digest),
            ];
            vectors.push(finish(
                "index_six",
                1,
                0,
                default_set(&ctx),
                0,
                "index_out_of_range",
                body,
                body_json(7, 2, &ctx.emitter(2), sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }
    }

    // -- high_s / wrong_recovery_id / non_guardian_signer -------------------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");

        // high_s
        {
            let sequence = 110u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 2,
                emitter_address: ctx.emitter(2),
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let mut sigs = sign_std(&ctx, &digest);
            sigs[0].s = sub_from_n(&sigs[0].s);
            vectors.push(finish(
                "high_s",
                1,
                0,
                default_set(&ctx),
                0,
                "high_s",
                body,
                body_json(7, 2, &ctx.emitter(2), sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }

        // wrong_recovery_id
        {
            let sequence = 111u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 2,
                emitter_address: ctx.emitter(2),
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let mut sigs = sign_std(&ctx, &digest);
            sigs[0].v ^= 1;
            vectors.push(finish(
                "wrong_recovery_id",
                1,
                0,
                default_set(&ctx),
                0,
                "wrong_guardian",
                body,
                body_json(7, 2, &ctx.emitter(2), sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }

        // non_guardian_signer
        {
            let sequence = 112u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 2,
                emitter_address: ctx.emitter(2),
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let mut sigs = sign_std(&ctx, &digest);
            sigs[2] = b::sign_digest(&[0x99u8; 32], 2, &digest);
            vectors.push(finish(
                "non_guardian_signer",
                1,
                0,
                default_set(&ctx),
                0,
                "wrong_guardian",
                body,
                body_json(7, 2, &ctx.emitter(2), sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }
    }

    // -- wrong_emitter_address / wrong_emitter_chain_right_address ----------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");

        // wrong_emitter_address: right chain (2), address doesn't match it.
        {
            let sequence = 113u64;
            let wrong_emitter = evm_token_addr("emitter-999");
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 2,
                emitter_address: wrong_emitter,
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sigs = sign_std(&ctx, &digest);
            vectors.push(finish(
                "wrong_emitter_address",
                1,
                0,
                default_set(&ctx),
                0,
                "wrong_emitter",
                body,
                body_json(7, 2, &wrong_emitter, sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }

        // wrong_emitter_chain_right_address: emitter_chain 3, chain-2 address.
        {
            let sequence = 114u64;
            let right_address = ctx.emitter(2);
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 7,
                emitter_chain: 3,
                emitter_address: right_address,
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to: RECIPIENT,
                    to_chain: 1,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sigs = sign_std(&ctx, &digest);
            vectors.push(finish(
                "wrong_emitter_chain_right_address",
                1,
                0,
                default_set(&ctx),
                0,
                "wrong_emitter",
                body,
                body_json(7, 3, &right_address, sequence),
                transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
                sigs,
                None,
            ));
        }
    }

    // -- wrong_to_chain: to_chain 2, submitted to verifier 1 ------------------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 115u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 2,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "wrong_to_chain",
            1,
            0,
            default_set(&ctx),
            0,
            "wrong_to_chain",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 2, &fee),
            sigs,
            None,
        ));
    }

    // -- wrong_token_chain: release to chain 2 whose token_chain is 3 --------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-3");
        let to = evm_to();
        let sequence = 4u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: ctx.rand_emitter,
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 3,
                to,
                to_chain: 2,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "wrong_token_chain",
            2,
            0,
            default_set(&ctx),
            0,
            "wrong_token_chain",
            body,
            body_json(0, 1, &ctx.rand_emitter, sequence),
            transfer_payload_json(&amount, &token, 3, &to, 2, &fee),
            sigs,
            None,
        ));
    }

    // -- fee_gt_amount --------------------------------------------------------
    {
        let amount = u256(1_000);
        let fee = u256(2_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 116u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "fee_gt_amount",
            1,
            0,
            default_set(&ctx),
            0,
            "fee_exceeds_amount",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- amount_over_u128: byte[15] = 1, the lowest byte of the upper 128 bits
    {
        let mut amount = [0u8; 32];
        amount[15] = 1;
        let fee = u256(0);
        let token = evm_token_addr("usdt-2");
        let sequence = 117u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "amount_over_u128",
            1,
            0,
            default_set(&ctx),
            0,
            "amount_overflow",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- payload_132_bytes: transfer payload truncated by one byte ------------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 118u64;
        let mut payload_bytes = b::Payload::Transfer(b::Transfer {
            amount,
            token_address: token,
            token_chain: 2,
            to: RECIPIENT,
            to_chain: 1,
            fee,
        })
        .encode();
        payload_bytes.pop();
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: payload_bytes,
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "payload_132_bytes",
            1,
            0,
            default_set(&ctx),
            0,
            "bad_payload",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- payload_id_9: first payload byte set to 9 -----------------------------
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 119u64;
        let mut payload_bytes = b::Payload::Transfer(b::Transfer {
            amount,
            token_address: token,
            token_chain: 2,
            to: RECIPIENT,
            to_chain: 1,
            fee,
        })
        .encode();
        payload_bytes[0] = 9;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: payload_bytes,
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "payload_id_9",
            1,
            0,
            default_set(&ctx),
            0,
            "bad_payload",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            PayloadJson::Transfer {
                id: 9,
                amount: big_dec(&amount),
                token_address: hex32(&token),
                token_chain: 2,
                to: hex32(&RECIPIENT),
                to_chain: 1,
                fee: big_dec(&fee),
            },
            sigs,
            None,
        ));
    }

    // -- version_2: envelope version byte 2, signatures still over the body ---
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 120u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "version_2",
            1,
            0,
            default_set(&ctx),
            0,
            "bad_version",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            Some(2),
        ));
    }

    // -- replay_eth: identical bytes to transfer_eth_usdt_6dp_ok ---------------
    {
        vectors.push(Vector {
            name: "replay_eth".to_string(),
            attestation: eth_attestation_hex,
            digest: eth_digest_hex,
            verifier_chain: 1,
            guardian_set_index: 0,
            sets: default_set(&ctx),
            current_set: 0,
            expect: "replay".to_string(),
            body: body_json(7, 2, &ctx.emitter(2), 3),
            payload: transfer_payload_json(&eth_amount, &eth_token, 2, &RECIPIENT, 1, &eth_fee),
            replay_of: Some("transfer_eth_usdt_6dp_ok".to_string()),
        });
    }

    // -- transfer_token_chain_mismatch --------------------------------------
    // A source transfer from chain 2's registered emitter naming an asset
    // whose home is chain 3. A source contract only ever custodies its own
    // chain's tokens, so `token_chain == emitter_chain` (spec 6.2); this is
    // the Rand-side twin of the `wrong_token_chain` release below.
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-3");
        let sequence = 121u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 3,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let sigs = sign_std(&ctx, &digest);
        vectors.push(finish(
            "transfer_token_chain_mismatch",
            1,
            0,
            default_set(&ctx),
            0,
            "wrong_token_chain",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 3, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    // -- release_wrong_emitter_eth / release_wrong_to_chain_eth /
    //    release_fee_gt_amount_eth ------------------------------------------
    // Rejected releases addressed to the Ethereum endpoint (verifier 2),
    // one per rule `RandBridgeBase.release` owns after `_verify`.
    {
        let to = evm_to();
        let token = evm_token_addr("usdt-2");

        // Not the Rand burn emitter.
        {
            let amount = u256(100_000_000);
            let fee = u256(1_000);
            let wrong_emitter = evm_token_addr("rand-emitter-impostor");
            let sequence = 5u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 0,
                emitter_chain: 1,
                emitter_address: wrong_emitter,
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to,
                    to_chain: 2,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sigs = sign_std(&ctx, &digest);
            vectors.push(finish(
                "release_wrong_emitter_eth",
                2,
                0,
                default_set(&ctx),
                0,
                "wrong_emitter",
                body,
                body_json(0, 1, &wrong_emitter, sequence),
                transfer_payload_json(&amount, &token, 2, &to, 2, &fee),
                sigs,
                None,
            ));
        }

        // Addressed to chain 3, submitted to the chain-2 endpoint.
        {
            let amount = u256(100_000_000);
            let fee = u256(1_000);
            let sequence = 6u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 0,
                emitter_chain: 1,
                emitter_address: ctx.rand_emitter,
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to,
                    to_chain: 3,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sigs = sign_std(&ctx, &digest);
            vectors.push(finish(
                "release_wrong_to_chain_eth",
                2,
                0,
                default_set(&ctx),
                0,
                "wrong_to_chain",
                body,
                body_json(0, 1, &ctx.rand_emitter, sequence),
                transfer_payload_json(&amount, &token, 2, &to, 3, &fee),
                sigs,
                None,
            ));
        }

        // `fee > amount`, the spec 3.6 rule on the payload itself.
        {
            let amount = u256(1_000);
            let fee = u256(2_000);
            let sequence = 7u64;
            let body = b::Body {
                timestamp: TIMESTAMP,
                nonce: 0,
                emitter_chain: 1,
                emitter_address: ctx.rand_emitter,
                sequence,
                consistency_level: 1,
                payload: b::Payload::Transfer(b::Transfer {
                    amount,
                    token_address: token,
                    token_chain: 2,
                    to,
                    to_chain: 2,
                    fee,
                })
                .encode(),
            };
            let digest = b::digest(&body.encode());
            let sigs = sign_std(&ctx, &digest);
            vectors.push(finish(
                "release_fee_gt_amount_eth",
                2,
                0,
                default_set(&ctx),
                0,
                "fee_exceeds_amount",
                body,
                body_json(0, 1, &ctx.rand_emitter, sequence),
                transfer_payload_json(&amount, &token, 2, &to, 2, &fee),
                sigs,
                None,
            ));
        }
    }

    // -- replay_release_eth: the exact bytes of release_to_eth_ok ----------
    {
        let original = vectors
            .iter()
            .find(|v| v.name == "release_to_eth_ok")
            .expect("release_to_eth_ok is generated above");
        let attestation = original.attestation.clone();
        let digest = original.digest.clone();
        let token = evm_token_addr("usdt-2");
        let to = evm_to();
        vectors.push(Vector {
            name: "replay_release_eth".to_string(),
            attestation,
            digest,
            verifier_chain: 2,
            guardian_set_index: 0,
            sets: default_set(&ctx),
            current_set: 0,
            expect: "replay".to_string(),
            body: body_json(0, 1, &ctx.rand_emitter, 0),
            payload: transfer_payload_json(&release_amount, &token, 2, &to, 2, &release_fee),
            replay_of: Some("release_to_eth_ok".to_string()),
        });
    }

    // -- bad_signature: signature 0's `r` zeroed -----------------------------
    // A structurally valid envelope whose first signature cannot recover to
    // anything: `r = 0` is off-curve for every recovery id. All three
    // verifiers must reject it with their own BadSignature code, and must
    // do so *before* mistaking `ecrecover`'s zero return for a guardian.
    {
        let amount = u256(100_000_000);
        let fee = u256(1_000);
        let token = evm_token_addr("usdt-2");
        let sequence = 122u64;
        let body = b::Body {
            timestamp: TIMESTAMP,
            nonce: 7,
            emitter_chain: 2,
            emitter_address: ctx.emitter(2),
            sequence,
            consistency_level: 1,
            payload: b::Payload::Transfer(b::Transfer {
                amount,
                token_address: token,
                token_chain: 2,
                to: RECIPIENT,
                to_chain: 1,
                fee,
            })
            .encode(),
        };
        let digest = b::digest(&body.encode());
        let mut sigs = sign_std(&ctx, &digest);
        sigs[0].r = [0u8; 32];
        vectors.push(finish(
            "bad_signature",
            1,
            0,
            default_set(&ctx),
            0,
            "bad_signature",
            body,
            body_json(7, 2, &ctx.emitter(2), sequence),
            transfer_payload_json(&amount, &token, 2, &RECIPIENT, 1, &fee),
            sigs,
            None,
        ));
    }

    let guardians = (0..6)
        .map(|i| GuardianEntry {
            secret: hex32(&ctx.secrets[i]),
            address: hex20(&ctx.addrs[i]),
        })
        .collect();

    let mut emitters = std::collections::BTreeMap::new();
    for chain in [2u16, 3, 4, 5] {
        emitters.insert(chain.to_string(), hex32(&ctx.emitter(chain)));
    }

    VectorsFile {
        guardians,
        governance_emitter: hex32(&ctx.governance_emitter),
        rand_emitter: hex32(&ctx.rand_emitter),
        emitters,
        now: NOW,
        vectors,
    }
}
