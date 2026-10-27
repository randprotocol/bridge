use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bridge_daemons::config::Config;
use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::sources::{self, Source};
use bridge_daemons::store::Store;
use bridge_daemons::{api, guardian};
use clap::Parser;

/// The Rand bridge guardian daemon: watch, check, sign, serve.
#[derive(Parser)]
struct Cli {
    /// The TOML configuration file (see daemons/config.example.toml).
    #[arg(long, env = "RAND_BRIDGE_CONFIG")]
    config: PathBuf,
    /// Clear a signing pause (a cap breach, BRG-1) after reviewing it, then
    /// exit. Prints what the pause was; needs no key.
    #[arg(long)]
    resume_signing: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    let section = config
        .guardian
        .clone()
        .ok_or_else(|| anyhow!("the config has no [guardian] section"))?;
    if cli.resume_signing {
        let store = Store::open(&config.data_dir)?;
        match bridge_daemons::limits::resume(&store)? {
            Some(p) => println!(
                "signing resumed; it was paused at {} on chain {} sequence {}: {}",
                p.at, p.chain, p.sequence, p.reason
            ),
            None => println!("signing was not paused"),
        }
        return Ok(());
    }

    // The key comes from the environment only, and leaves it at once so no
    // child process or crash dump of the environment carries it.
    let secret =
        std::env::var(&section.key_env).map_err(|_| anyhow!("{} is not set", section.key_env))?;
    std::env::remove_var(&section.key_env);
    let key = GuardianKey::from_hex(&secret)?;
    drop(secret);
    tracing::info!("guardian {}", hex::encode(key.address()));

    // The post-quantum half (spec/PQ-COSIGNATURE.md): a second key, and the
    // Rand chain id its co-signatures name. The id is configuration, checked
    // against the node before the first poll (below) — never taken from it.
    let pq = match std::env::var(&section.pq_seed_env)
        .ok()
        .filter(|v| !v.is_empty())
    {
        Some(seed) => {
            std::env::remove_var(&section.pq_seed_env);
            let rand_chain_id = config
                .rand
                .chain_id
                .ok_or_else(|| anyhow!("rand.chain_id is required to co-sign"))?;
            let pq_key = bridge_daemons::pq::PqKey::from_seed_hex(&seed)?;
            tracing::info!(
                "co-signing for Rand chain {rand_chain_id}; PQ public key {}…",
                &hex::encode(pq_key.public_key())[..16]
            );
            Some(guardian::PqSigner {
                key: pq_key,
                rand_chain_id,
            })
        }
        None => {
            tracing::warn!(
                "{} is not set: deposits will carry no Dilithium2 co-signature",
                section.pq_seed_env
            );
            None
        }
    };
    let store = Store::open(&config.data_dir)?;
    let emitters = config.emitters()?;
    let limits = section
        .limits
        .as_ref()
        .map(bridge_daemons::limits::Limits::new)
        .transpose()?;
    match &section.limits {
        Some(l) => tracing::info!(
            "caps: {} per transfer, {} per {} s per token and direction ({} token overrides)",
            l.per_transfer,
            l.per_window,
            l.window_secs,
            l.token.len()
        ),
        None => tracing::warn!(
            "no [guardian.limits]: this guardian signs without per-transfer or per-window caps (BRG-1)"
        ),
    }
    if let Some(p) = bridge_daemons::limits::paused(&store)? {
        tracing::warn!(
            "signing is PAUSED (chain {} sequence {}: {}); rand-guardian --resume-signing clears it",
            p.chain,
            p.sequence,
            p.reason
        );
    }
    let guards = guardian::Guards {
        limits: limits.as_ref(),
    };

    let listener = tokio::net::TcpListener::bind(&section.listen)
        .await
        .with_context(|| format!("binding {}", section.listen))?;
    tracing::info!("signature API on {}", section.listen);
    let router = api::router(store.clone(), key.address());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("signature API stopped: {e}");
        }
    });

    // Each chain through its configured providers (BR-4): with two or more,
    // nothing is signed that one provider alone reports.
    let evm = config
        .evm
        .iter()
        .map(|cfg| {
            let (urls, quorum) = cfg.providers();
            sources::describe_providers(&cfg.name, &urls, quorum);
            sources::evm_quorum(cfg)
        })
        .collect::<Result<Vec<_>>>()?;
    let solana = config
        .solana
        .as_ref()
        .map(|cfg| {
            let (urls, quorum) = cfg.providers();
            sources::describe_providers(&cfg.name, &urls, quorum);
            sources::solana_quorum(cfg)
        })
        .transpose()?;
    let rand = {
        let (urls, quorum) = config.rand.providers();
        sources::describe_providers("rand", &urls, quorum);
        sources::rand_quorum(&config.rand)?
    };

    // Before the first poll (BR-401): the Rand node answers and serves
    // `rand.chain_id` — configured, never taken from the node, and the node
    // must agree, not merely be silent — and the Rand cursor this data dir
    // resumes from is not past the chain's burn_sequence. Any of these stops
    // the daemon here, with the reason; systemd restarts it once it is fixed.
    {
        let rpc = bridge_daemons::rpc::JsonRpc::new(&config.rand.rpc);
        let cursor = store.cursor(rand.name())?.unwrap_or_else(|| rand.start());
        bridge_daemons::sources::rand::check_startup(&rpc, config.rand.chain_id, &cursor).await?;
    }

    loop {
        // A source that fails is retried on the next round; one chain's RPC
        // being down must not stop the others from being signed. An
        // equivocation is the exception: it is fatal by design.
        for source in &evm {
            report(
                source_name(source),
                guardian::step_guarded(source, &store, &key, pq.as_ref(), &emitters, &guards).await,
            )?;
        }
        if let Some(source) = &solana {
            report(
                source_name(source),
                guardian::step_guarded(source, &store, &key, pq.as_ref(), &emitters, &guards).await,
            )?;
        }
        report(
            "rand",
            guardian::step_guarded(&rand, &store, &key, pq.as_ref(), &emitters, &guards).await,
        )?;

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.poll_secs)) => {}
            _ = tokio::signal::ctrl_c() => { tracing::info!("stopping"); return Ok(()); }
        }
    }
}

fn source_name<S: bridge_daemons::sources::Source>(s: &S) -> &str {
    s.name()
}

fn report(name: &str, result: Result<usize>) -> Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(e) if e.downcast_ref::<guardian::Equivocation>().is_some() => Err(e),
        Err(e) => {
            tracing::warn!("{name}: {e:#}");
            Ok(())
        }
    }
}
