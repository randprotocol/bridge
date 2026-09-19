use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bridge_daemons::config::Config;
use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::sources::{evm::EvmSource, rand::RandSource, solana::SolanaSource};
use bridge_daemons::store::Store;
use bridge_daemons::{api, guardian};
use clap::Parser;

/// The Rand bridge guardian daemon: watch, check, sign, serve.
#[derive(Parser)]
struct Cli {
    /// The TOML configuration file (see daemons/config.example.toml).
    #[arg(long, env = "RAND_BRIDGE_CONFIG")]
    config: PathBuf,
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

    // The key comes from the environment only, and leaves it at once so no
    // child process or crash dump of the environment carries it.
    let secret =
        std::env::var(&section.key_env).map_err(|_| anyhow!("{} is not set", section.key_env))?;
    std::env::remove_var(&section.key_env);
    let key = GuardianKey::from_hex(&secret)?;
    drop(secret);
    tracing::info!("guardian {}", hex::encode(key.address()));

    let store = Store::open(&config.data_dir)?;
    let emitters = config.emitters()?;

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

    let evm: Vec<EvmSource> = config
        .evm
        .iter()
        .map(EvmSource::new)
        .collect::<Result<_>>()?;
    let solana = config.solana.as_ref().map(SolanaSource::new).transpose()?;
    let rand = RandSource::new(&config.rand);

    loop {
        // A source that fails is retried on the next round; one chain's RPC
        // being down must not stop the others from being signed. An
        // equivocation is the exception: it is fatal by design.
        for source in &evm {
            report(
                source_name(source),
                guardian::step(source, &store, &key, &emitters).await,
            )?;
        }
        if let Some(source) = &solana {
            report(
                source_name(source),
                guardian::step(source, &store, &key, &emitters).await,
            )?;
        }
        report("rand", guardian::step(&rand, &store, &key, &emitters).await)?;

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
