//! Prints the Dilithium2 public key (hex) of the seed in `PQ_SEED` (32 bytes, hex): the entry a
//! chain's `pq_guardians` lists for that guardian. The seed comes from the environment only.
//!
//!     PQ_SEED=$(cat pq-next.seed) cargo run --release --example pq_pubkey
fn main() -> anyhow::Result<()> {
    let seed = std::env::var("PQ_SEED").map_err(|_| anyhow::anyhow!("PQ_SEED is not set"))?;
    let key = bridge_daemons::pq::PqKey::from_seed_hex(&seed)?;
    println!("{}", hex::encode(key.public_key()));
    Ok(())
}
