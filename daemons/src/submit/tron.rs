//! `release(bytes)` on Tron, over the node's HTTP API: the node builds the
//! transaction (`wallet/triggersmartcontract`), the relayer signs its id and
//! broadcasts it.
//!
//! The node is not trusted with the key's signature: before signing, the
//! transaction id is recomputed as `sha256(raw_data)`, and the raw bytes must
//! contain exactly the contract and calldata this relayer asked for. The
//! relayer key should hold only what it needs for energy.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bridge_codec::Attestation;
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{abi_encode_bytes, consumed_calldata, release_calldata, Outcome};
use crate::config::{address20, EvmConfig};
use crate::crypto::{address_of, sign_recoverable};

pub struct TronSubmitter {
    name: String,
    api: String,
    http: reqwest::Client,
    contract: [u8; 20],
    key: SigningKey,
    from: [u8; 20],
    fee_limit: u64,
}

fn tron_hex(addr: &[u8; 20]) -> String {
    format!("41{}", hex::encode(addr))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

impl TronSubmitter {
    pub fn new(cfg: &EvmConfig, secret_hex: &str, fee_limit: u64) -> Result<TronSubmitter> {
        let bytes = hex::decode(secret_hex.trim().trim_start_matches("0x"))
            .map_err(|_| anyhow!("relayer key is not hex"))?;
        let key = SigningKey::from_slice(&bytes)
            .map_err(|_| anyhow!("relayer key is not a valid scalar"))?;
        let from = address_of(key.verifying_key());
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        Ok(TronSubmitter {
            name: cfg.name.clone(),
            api: cfg.rpc.trim_end_matches('/').to_string(),
            http,
            contract: address20(&cfg.contract)?,
            key,
            from,
            fee_limit,
        })
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let url = format!("{}/{path}", self.api);
        self.http
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{}: POST {path}", self.name))?
            .error_for_status()?
            .json()
            .await
            .with_context(|| format!("{}: {path} did not answer JSON", self.name))
    }

    pub async fn is_consumed(&self, digest: &[u8; 32]) -> Result<bool> {
        let v = self
            .post(
                "wallet/triggerconstantcontract",
                json!({
                    "owner_address": tron_hex(&self.from),
                    "contract_address": tron_hex(&self.contract),
                    "function_selector": "consumed(bytes32)",
                    "parameter": hex::encode(&consumed_calldata(digest)[4..]),
                }),
            )
            .await?;
        let result = v["constant_result"][0]
            .as_str()
            .ok_or_else(|| anyhow!("{}: consumed() gave no result", self.name))?;
        Ok(result.ends_with('1'))
    }

    pub async fn release(&self, attestation: &Attestation, digest: &[u8; 32]) -> Result<Outcome> {
        let encoded = attestation.encode();
        self.submit(
            "release(bytes)",
            &encoded,
            release_calldata(attestation),
            digest,
        )
        .await
    }

    /// `submitGuardianSetUpgrade(bytes)`: open to anyone, like `release`.
    pub async fn guardian_set_upgrade(
        &self,
        attestation: &[u8],
        digest: &[u8; 32],
    ) -> Result<Outcome> {
        let calldata = crate::governance::upgrade_calldata(attestation);
        self.submit(
            "submitGuardianSetUpgrade(bytes)",
            attestation,
            calldata,
            digest,
        )
        .await
    }

    /// One `bytes`-taking call: the node builds it, this checks and signs it.
    async fn submit(
        &self,
        function: &str,
        argument: &[u8],
        calldata: Vec<u8>,
        digest: &[u8; 32],
    ) -> Result<Outcome> {
        if self.is_consumed(digest).await? {
            return Ok(Outcome::AlreadyDone);
        }
        let parameter = abi_encode_bytes(argument);
        let built = self
            .post(
                "wallet/triggersmartcontract",
                json!({
                    "owner_address": tron_hex(&self.from),
                    "contract_address": tron_hex(&self.contract),
                    "function_selector": function,
                    "parameter": hex::encode(&parameter),
                    "fee_limit": self.fee_limit,
                    "call_value": 0,
                }),
            )
            .await?;
        if built["result"]["result"].as_bool() != Some(true) {
            bail!(
                "{}: node refused to build the call: {}",
                self.name,
                built["result"]
            );
        }
        let mut tx = built["transaction"].clone();
        let raw = hex::decode(tx["raw_data_hex"].as_str().unwrap_or_default())
            .map_err(|_| anyhow!("raw_data_hex is not hex"))?;
        let id: [u8; 32] = Sha256::digest(&raw).into();
        if tx["txID"].as_str() != Some(hex::encode(id).as_str()) {
            bail!("{}: node's txID is not the hash of its raw_data", self.name);
        }
        let mut contract = vec![0x41];
        contract.extend_from_slice(&self.contract);
        if !contains(&raw, &contract) || !contains(&raw, &calldata) {
            bail!(
                "{}: node built a transaction that is not our call",
                self.name
            );
        }

        let sig = sign_recoverable(&self.key, &id)?;
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&sig.r);
        sig_bytes.extend_from_slice(&sig.s);
        sig_bytes.push(27 + sig.v);
        tx["signature"] = json!([hex::encode(sig_bytes)]);

        let sent = self.post("wallet/broadcasttransaction", tx).await?;
        if sent["result"].as_bool() != Some(true) {
            bail!("{}: broadcast refused: {sent}", self.name);
        }
        let txid = hex::encode(id);
        tracing::info!("{}: {function} sent in {txid}", self.name);

        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let info = self
                .post("wallet/gettransactioninfobyid", json!({ "value": txid }))
                .await?;
            let Some(result) = info["receipt"]["result"].as_str() else {
                continue;
            };
            if result == "SUCCESS" {
                return Ok(Outcome::Submitted(txid));
            }
            if self.is_consumed(digest).await? {
                return Ok(Outcome::AlreadyDone);
            }
            bail!("{}: {function} {txid} ended {result}", self.name);
        }
        bail!(
            "{}: {function} {txid} not confirmed after three minutes",
            self.name
        )
    }
}
