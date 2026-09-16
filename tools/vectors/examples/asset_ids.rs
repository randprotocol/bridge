//! Prints the Rand asset id of every approved token (docs/architecture.md
//! §10.1): `blake3("rand-bridge-asset" || token_chain BE u16 || token_address)`,
//! computed by the fullnode's own `asset_id`, so the table in the docs can be
//! regenerated whenever the domain string or the token list changes.
//!
//! `cd tools/vectors && cargo run --release --example asset_ids`

use randprotocol_core::bridge::asset_id;

fn left_pad20(hex20: &str) -> [u8; 32] {
    let raw = hex::decode(hex20.trim_start_matches("0x")).expect("hex");
    assert_eq!(raw.len(), 20);
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&raw);
    out
}

fn solana_mint(b58: &str) -> [u8; 32] {
    // Minimal base58 decode (Bitcoin alphabet) so this example needs no
    // extra dependency.
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num = vec![0u8; 0];
    for c in b58.bytes() {
        let d = ALPHABET.iter().position(|&a| a == c).expect("base58 char") as u32;
        let mut carry = d;
        for byte in num.iter_mut().rev() {
            let v = (*byte as u32) * 58 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading = b58.bytes().take_while(|&c| c == b'1').count();
    let mut out = vec![0u8; leading];
    out.extend(num);
    assert_eq!(out.len(), 32, "a Solana pubkey is 32 bytes");
    out.try_into().unwrap()
}

fn main() {
    let rows: [(u16, &str, [u8; 32]); 8] = [
        (2, "USDT", left_pad20("0xdAC17F958D2ee523a2206206994597C13D831ec7")),
        (2, "USDC", left_pad20("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")),
        (3, "USDT", left_pad20("0x55d398326f99059fF775485246999027B3197955")),
        (3, "USDC", left_pad20("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d")),
        (4, "USDT", left_pad20("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c")),
        (4, "USDC", left_pad20("0x3487b63d30b5b2c87fb7ffa8bcfade38eaac1abe")),
        (5, "USDT", solana_mint("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB")),
        (5, "USDC", solana_mint("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")),
    ];
    println!("| chain | token | `token_address` (32 bytes) | Rand asset id |");
    println!("|---|---|---|---|");
    for (chain, token, addr) in rows {
        let id = asset_id(chain, &addr);
        println!(
            "| {chain} | {token} | `0x{}` | `0x{}` |",
            hex::encode(addr),
            hex::encode(id.as_bytes())
        );
    }
}
