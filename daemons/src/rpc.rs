//! A minimal JSON-RPC 2.0 client: the daemons speak to four kinds of node and
//! need nothing from any of them beyond request/response.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct JsonRpc {
    url: String,
    http: reqwest::Client,
}

impl JsonRpc {
    pub fn new(url: &str) -> JsonRpc {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        JsonRpc {
            url: url.to_string(),
            http,
        }
    }

    /// The origin only: RPC URLs embed provider API keys.
    pub fn shown(&self) -> String {
        let rest = self.url.split("://").nth(1).unwrap_or(&self.url);
        let host = rest.split(['/', '?']).next().unwrap_or(rest);
        host.rsplit('@').next().unwrap_or(host).to_string()
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response: Value = self
            .http
            .post(&self.url)
            .json(&request)
            .send()
            .await
            .with_context(|| format!("{method} to {}", self.shown()))?
            .error_for_status()
            .with_context(|| format!("{method} to {}", self.shown()))?
            .json()
            .await
            .with_context(|| format!("{method}: response is not JSON"))?;
        if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
            bail!("{method}: {error}");
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: no result"))
    }
}

/// `"0x1f"` -> 31.
pub fn quantity(v: &Value) -> Result<u64> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected a hex quantity, got {v}"))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|_| anyhow!("bad hex quantity {s}"))
}

pub fn quantity_u128(v: &Value) -> Result<u128> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected a hex quantity, got {v}"))?;
    u128::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| anyhow!("bad hex quantity {s}"))
}

pub fn hex_data(v: &Value) -> Result<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected hex data, got {v}"))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|_| anyhow!("bad hex data"))
}
