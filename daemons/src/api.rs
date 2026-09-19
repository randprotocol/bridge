//! The guardian's signature API, and the relayer's client for it.
//!
//! Guardians do not talk to each other and do not assemble anything: each
//! serves its own signature per `(emitter chain, sequence)`, and whoever
//! wants a transfer completed collects a quorum. The API gives away nothing
//! that is not about to be public on a destination chain.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, RawSignature};
use crate::message::Observed;
use crate::store::Store;

pub const SIGNED: &str = "signed";

/// One guardian's signature over one message, as stored and as served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Observed,
    /// The signer's 20-byte guardian address, hex.
    pub guardian: String,
    pub signature: RawSignature,
    /// The Dilithium2 co-signature (hex, 2,420 bytes) for a message addressed
    /// to Rand, when this guardian holds a PQ key (`spec/PQ-COSIGNATURE.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
}

/// What a guardian returned for one message, after the ECDSA signature has
/// been checked. The co-signature is checked by whoever knows the PQ set.
pub struct Collected {
    pub address: [u8; 20],
    pub signature: RawSignature,
    pub pq_signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Health {
    pub guardian: String,
}

struct ApiState {
    store: Store,
    guardian: String,
}

pub fn router(store: Store, guardian: [u8; 20]) -> Router {
    let state = Arc::new(ApiState {
        store,
        guardian: hex::encode(guardian),
    });
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/signature/:chain/:sequence", get(signature))
        .with_state(state)
}

async fn health(State(state): State<Arc<ApiState>>) -> Json<Health> {
    Json(Health {
        guardian: state.guardian.clone(),
    })
}

async fn signature(
    State(state): State<Arc<ApiState>>,
    Path((chain, sequence)): Path<(u16, u64)>,
) -> Result<Json<SignedMessage>, StatusCode> {
    match state
        .store
        .read_message::<SignedMessage>(SIGNED, chain, sequence)
    {
        Ok(Some(signed)) => Ok(Json(signed)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("reading signature {chain}/{sequence}: {e:#}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The relayer's view of one guardian.
#[derive(Clone)]
pub struct GuardianClient {
    origin: String,
    http: reqwest::Client,
}

impl GuardianClient {
    pub fn new(origin: &str) -> GuardianClient {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        GuardianClient {
            origin: origin.trim_end_matches('/').to_string(),
            http,
        }
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// This guardian's signature over `expected`, if it has one yet.
    ///
    /// Nothing the guardian says is taken on trust: the signature must
    /// recover, over the digest of the body the *relayer* observed, to the
    /// address it is returned with.
    pub async fn signature(&self, expected: &Observed) -> Result<Option<Collected>> {
        let url = format!(
            "{}/v1/signature/{}/{}",
            self.origin, expected.emitter_chain, expected.sequence
        );
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let signed: SignedMessage = response
            .error_for_status()?
            .json()
            .await
            .with_context(|| format!("GET {url}"))?;
        if signed.message.body != expected.body {
            bail!(
                "{}: signed a different body for {}/{}",
                self.origin,
                expected.emitter_chain,
                expected.sequence
            );
        }
        let address = crypto::recover(&expected.digest, &signed.signature)?;
        let pq_signature = signed
            .pq_signature
            .as_deref()
            .and_then(|s| hex::decode(s).ok());
        Ok(Some(Collected {
            address,
            signature: signed.signature,
            pq_signature,
        }))
    }
}
