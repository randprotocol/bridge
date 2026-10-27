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
    /// Pause all signing (an operator's act; nothing pauses on its own), then
    /// exit. Needs no key.
    #[arg(long, value_name = "REASON")]
    pause_signing: Option<String>,
    /// Clear an operator's pause, then exit. Needs no key.
    #[arg(long)]
    resume_signing: bool,
    /// Sign one transfer withheld over the per-transfer cap (BRG-1), after
    /// review, then exit: `<chain>:<sequence>`. Needs the guardian's keys.
    #[arg(long, value_name = "CHAIN:SEQUENCE")]
    release_held: Option<String>,
    /// List the withheld transfers and exit.
    #[arg(long)]
    list_held: bool,
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
    if let Some(reason) = &cli.pause_signing {
        let store = Store::open(&config.data_dir)?;
        bridge_daemons::limits::pause(&store, bridge_daemons::limits::now(), reason)?;
        println!("signing paused: {reason}");
        return Ok(());
    }
    if cli.resume_signing {
        let store = Store::open(&config.data_dir)?;
        match bridge_daemons::limits::resume(&store)? {
            Some(p) => println!("signing resumed; it was paused at {}: {}", p.at, p.reason),
            None => println!("signing was not paused"),
        }
        return Ok(());
    }
    if cli.list_held {
        let store = Store::open(&config.data_dir)?;
        for (chain, sequence) in bridge_daemons::limits::held(&store)? {
            let h: bridge_daemons::limits::Held = store
                .read_message(bridge_daemons::limits::HELD, chain, sequence)?
                .ok_or_else(|| anyhow!("held record {chain}/{sequence} vanished"))?;
            println!("{chain}:{sequence}  held at {}  {}", h.at, h.reason);
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
    if let Some(target) = &cli.release_held {
        let (chain, sequence) = target
            .split_once(':')
            .and_then(|(c, s)| Some((c.parse::<u16>().ok()?, s.parse::<u64>().ok()?)))
            .ok_or_else(|| anyhow!("--release-held takes <chain>:<sequence>, got {target:?}"))?;
        let guards = guardian::Guards {
            limits: limits.as_ref(),
            ..Default::default()
        };
        let signed = guardian::release_held(
            &store,
            &key,
            pq.as_ref(),
            &emitters,
            &guards,
            chain,
            sequence,
            bridge_daemons::limits::now(),
        )?;
        println!(
            "chain {chain} sequence {sequence} released: {}",
            if signed { "signed" } else { "not signed (see the log)" }
        );
        return Ok(());
    }
    if let Some(p) = bridge_daemons::limits::paused(&store)? {
        tracing::warn!(
            "signing is PAUSED by an operator ({}); rand-guardian --resume-signing clears it",
            p.reason
        );
    }
    let held = bridge_daemons::limits::held(&store)?;
    if !held.is_empty() {
        tracing::error!(
            "{} transfer(s) withheld over the per-transfer cap: {:?}; review, then \
             rand-guardian --release-held <chain>:<sequence>",
            held.len(),
            held
        );
    }
    // BR-502: the peers asked before a first signature, and the set whose
    // signatures count there (refreshed every round from the Rand node).
    let peers: Vec<bridge_daemons::api::GuardianClient> = section
        .peers
        .iter()
        .map(|p| bridge_daemons::api::GuardianClient::new(p))
        .collect();
    if peers.is_empty() {
        tracing::warn!(
            "no guardian.peers: a second body for a (chain, sequence) is refused only while this \
             guardian's own signed/ record of the first one exists (BR-502)"
        );
    } else {
        let mut up = 0;
        for p in &peers {
            match p.record(0, 0).await {
                Ok(_) => up += 1,
                Err(e) => tracing::warn!("peer {}: {e:#}", p.origin()),
            }
        }
        tracing::info!(
            "{up} of {} peers answer; each first signature is checked against them",
            peers.len()
        );
    }
    let rand_rpc = bridge_daemons::rpc::JsonRpc::new(&config.rand.rpc);
    let mut known: Vec<[u8; 20]> = Vec::new();

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
        if !peers.is_empty() {
            match bridge_daemons::sources::rand::bridge_state(&rand_rpc).await {
                Ok(Some(state)) => known = state.guardians,
                Ok(None) => {}
                Err(e) => tracing::warn!("reading the guardian set for the peer check: {e:#}"),
            }
        }
        let guards = guardian::Guards {
            limits: limits.as_ref(),
            peers: &peers,
            known: &known,
        };
        if let Err(e) =
            guardian::retry_deferred(&store, &key, pq.as_ref(), &emitters, &guards).await
        {
            tracing::warn!("deferred transfers: {e:#}");
        }
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
