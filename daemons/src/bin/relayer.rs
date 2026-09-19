use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use bridge_daemons::api::GuardianClient;
use bridge_daemons::config::{address20, hex32, Config, EvmKind, RelayerConfig};
use bridge_daemons::relayer::{self, Destinations, EndpointSubmitter, GuardianSet, Progress};
use bridge_daemons::rpc::JsonRpc;
use bridge_daemons::sources::{evm::EvmSource, rand::RandSource, solana::SolanaSource};
use bridge_daemons::store::Store;
use bridge_daemons::submit::evm::EvmSubmitter;
use bridge_daemons::submit::process::{RandSubmitter, SolanaSubmitter};
use bridge_daemons::submit::tron::TronSubmitter;
use clap::Parser;

/// The Rand bridge relayer daemon: collect a quorum, submit.
#[derive(Parser)]
struct Cli {
    /// The TOML configuration file (see daemons/config.example.toml).
    #[arg(long, env = "RAND_BRIDGE_CONFIG")]
    config: PathBuf,
}

/// Reads a key from the environment and removes it from there, so the tools
/// this daemon spawns never inherit it.
fn take_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok().filter(|v| !v.is_empty());
    std::env::remove_var(name);
    value
}

fn destinations(config: &Config, section: &RelayerConfig) -> Result<Destinations> {
    let evm_key = take_env(&section.evm_key_env);
    let tron_key = take_env(&section.tron_key_env);
    let mut endpoints = BTreeMap::new();
    for e in &config.evm {
        let submitter = match e.kind {
            EvmKind::Evm => evm_key
                .as_deref()
                .map(|k| EvmSubmitter::new(e, k).map(EndpointSubmitter::Evm)),
            EvmKind::Tron => tron_key.as_deref().map(|k| {
                TronSubmitter::new(e, k, section.tron_fee_limit).map(EndpointSubmitter::Tron)
            }),
        };
        match submitter {
            Some(s) => {
                endpoints.insert(e.chain, s?);
            }
            None => tracing::warn!(
                "{}: no relayer key in the environment; releases there are skipped",
                e.name
            ),
        }
    }
    let scratch = config.data_dir.join("scratch");
    let solana = match (&config.solana, &section.solana_cli) {
        (Some(s), Some(cli)) => Some(SolanaSubmitter {
            cli: cli.clone(),
            rpc: s.rpc.clone(),
            program: s.program.clone(),
            scratch: scratch.clone(),
        }),
        _ => None,
    };
    let rand = section.rand_cli.as_ref().map(|cli| RandSubmitter {
        cli: cli.clone(),
        extra_args: section.rand_cli_args.clone(),
        scratch: scratch.clone(),
    });
    Ok(Destinations {
        endpoints,
        solana,
        rand,
        min_relayer_fee: section.min_relayer_fee,
    })
}

/// The set on Rand when there is a Rand chain to ask, the configured one
/// otherwise.
async fn guardian_set(rand: &JsonRpc, section: &RelayerConfig) -> Result<GuardianSet> {
    match bridge_daemons::sources::rand::bridge_state(rand).await {
        Ok(Some(state)) => {
            let rand_chain_id = bridge_daemons::sources::rand::chain_id(rand).await.ok();
            return Ok(GuardianSet {
                index: state.guardian_set_index,
                keys: state.guardians,
                pq_keys: state.pq_guardians,
                rand_chain_id,
            });
        }
        Ok(None) => {}
        Err(e) => tracing::debug!("rand_getBridgeState: {e:#}"),
    }
    if section.guardian_addresses.is_empty() {
        return Err(anyhow!(
            "the Rand node serves no bridge state and relayer.guardian_addresses is empty"
        ));
    }
    let keys = section
        .guardian_addresses
        .iter()
        .map(|a| address20(a))
        .collect::<Result<Vec<_>>>()?;
    Ok(GuardianSet {
        index: section.guardian_set_index,
        keys,
        pq_keys: Vec::new(),
        rand_chain_id: None,
    })
}

#[derive(serde::Deserialize)]
struct Registration {
    recipient_hash: String,
    address: String,
}

async fn register(State(store): State<Arc<Store>>, Json(r): Json<Registration>) -> StatusCode {
    let Ok(hash) = hex32(&r.recipient_hash) else {
        return StatusCode::BAD_REQUEST;
    };
    if !r.address.starts_with("rand1") || r.address.len() > 8192 {
        return StatusCode::BAD_REQUEST;
    }
    match relayer::register_recipient(&store, &hash, &r.address) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
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
        .relayer
        .clone()
        .ok_or_else(|| anyhow!("the config has no [relayer] section"))?;
    let store = Store::open(&config.data_dir)?;
    let destinations = destinations(&config, &section)?;
    let guardians: Vec<GuardianClient> = section
        .guardians
        .iter()
        .map(|g| GuardianClient::new(g))
        .collect();

    if let Some(file) = &section.recipients_file {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let table: BTreeMap<String, String> =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
        for (hash, address) in table {
            relayer::register_recipient(&store, &hex32(&hash)?, &address)?;
        }
    }
    if let Some(listen) = &section.listen {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding {listen}"))?;
        tracing::info!("recipient registration on {listen}");
        let router = Router::new()
            .route("/v1/recipients", post(register))
            .with_state(Arc::new(store.clone()));
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("registration API stopped: {e}");
            }
        });
    }

    let evm: Vec<EvmSource> = config
        .evm
        .iter()
        .map(EvmSource::new)
        .collect::<Result<_>>()?;
    let solana = config.solana.as_ref().map(SolanaSource::new).transpose()?;
    let rand = RandSource::new(&config.rand);
    let rand_rpc = JsonRpc::new(&config.rand.rpc);

    loop {
        for source in &evm {
            if let Err(e) = relayer::observe(source, &store).await {
                tracing::warn!("{e:#}");
            }
        }
        if let Some(source) = &solana {
            if let Err(e) = relayer::observe(source, &store).await {
                tracing::warn!("{e:#}");
            }
        }
        if let Err(e) = relayer::observe(&rand, &store).await {
            tracing::warn!("rand: {e:#}");
        }

        match guardian_set(&rand_rpc, &section).await {
            Ok(set) => {
                for message in relayer::pending(&store)? {
                    let (chain, sequence) = (message.emitter_chain, message.sequence);
                    match relayer::relay_one(&message, &store, &guardians, &set, &destinations)
                        .await
                    {
                        Ok(Progress::Done(outcome)) => {
                            tracing::info!(chain, sequence, "relayed: {outcome:?}")
                        }
                        Ok(progress) => tracing::debug!(chain, sequence, "{progress:?}"),
                        Err(e) => tracing::warn!(chain, sequence, "{e:#}"),
                    }
                }
            }
            Err(e) => tracing::warn!("{e:#}"),
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.poll_secs)) => {}
            _ = tokio::signal::ctrl_c() => { tracing::info!("stopping"); return Ok(()); }
        }
    }
}
