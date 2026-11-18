//! Whether the providers a chain is read through are independent (BR-4).
//!
//! The quorum read ([`crate::sources::Quorum`]) signs nothing one provider
//! alone reports. That holds only if the providers are different parties on
//! the same chain. Two URLs of one operator are one party, and a provider
//! that serves another network agrees with nobody. Two checks:
//!
//! - **Static, at config load** ([`independence_gap`]): with an `rpc_quorum`
//!   of two or more, no single operator's URLs may be enough to meet it. The
//!   operator of a URL is taken from its host ([`operator_of`]).
//! - **Live, on request** ([`probe`], `rand-guardian --check-providers`): each
//!   provider is asked which chain it serves, and the chain passes only when
//!   a quorum of providers, from at least two operators when the quorum is
//!   two or more, name the same chain — and, for Rand, the configured one.
//!   Read-only: one identity call per provider.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use serde_json::json;

use crate::config::{Config, EvmKind};
use crate::rpc::JsonRpc;

/// The party behind an RPC URL, as far as its host tells.
///
/// A named host is reduced to its last two labels (`ethereum-rpc.publicnode.com`
/// and `bsc-rpc.publicnode.com` are both `publicnode.com`), so two endpoints of
/// one provider count once. This is not the public-suffix list: under a
/// two-label suffix (`example.co.uk`) different parties share an operator name
/// here, which errs towards refusing. An IP address, `localhost` or a
/// single-label host is taken with its port: these are local processes and
/// forwards, each configured on purpose.
pub fn operator_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let hostport = authority.rsplit('@').next().unwrap_or(authority).to_ascii_lowercase();
    // [v6]:port, host:port, host
    let host = if let Some(end) = hostport.find(']') {
        &hostport[..=end]
    } else {
        hostport.split(':').next().unwrap_or(&hostport)
    };
    let is_ip = host.starts_with('[') || host.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()));
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if is_ip || labels.len() < 2 {
        return hostport;
    }
    labels[labels.len() - 2..].join(".")
}

/// Why `urls` at `quorum` do not make a single lying operator harmless, or
/// `None` when they do. A quorum of one makes no such claim and is not
/// judged here (the guardian warns about it at startup).
pub fn independence_gap(what: &str, urls: &[String], quorum: usize) -> Option<String> {
    if quorum < 2 {
        return None;
    }
    let mut by_operator: BTreeMap<String, usize> = BTreeMap::new();
    for u in urls {
        *by_operator.entry(operator_of(u)).or_default() += 1;
    }
    let (operator, most) = by_operator.iter().max_by_key(|(_, n)| **n)?;
    if *most >= quorum {
        return Some(format!(
            "{what}: {most} of the {} RPCs are {operator}'s, enough to meet rpc_quorum {quorum} on \
             their own; a quorum must need at least two operators (BR-4). List providers run by \
             different parties, or raise rpc_quorum above {most}",
            urls.len()
        ));
    }
    None
}

/// What one provider said about the chain it serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The provider's host (never the URL: it may carry an API key).
    pub shown: String,
    pub operator: String,
    /// The chain it names, or why it did not.
    pub identity: Result<String, String>,
}

/// One chain's providers, asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainReport {
    pub name: String,
    pub quorum: usize,
    pub answers: Vec<Answer>,
    /// The chain the config says this is, when it says (Rand).
    pub expected: Option<String>,
}

impl ChainReport {
    /// `Ok(identity)` when a quorum of providers name the same chain — from
    /// at least two operators when the quorum is two or more — and it is the
    /// expected one. `Err` says what is short.
    pub fn verdict(&self) -> Result<String, String> {
        let mut groups: BTreeMap<&str, Vec<&Answer>> = BTreeMap::new();
        for a in &self.answers {
            if let Ok(id) = &a.identity {
                groups.entry(id.as_str()).or_default().push(a);
            }
        }
        let Some((id, agreeing)) = groups.iter().max_by_key(|(_, v)| v.len()) else {
            return Err(format!("no provider answered; {} needed", self.quorum));
        };
        if agreeing.len() < self.quorum {
            return Err(format!(
                "{} of {} providers name chain {id}; {} needed{}",
                agreeing.len(),
                self.answers.len(),
                self.quorum,
                if groups.len() > 1 { " (the providers name different chains)" } else { "" }
            ));
        }
        let operators: std::collections::BTreeSet<&str> = agreeing.iter().map(|a| a.operator.as_str()).collect();
        if self.quorum >= 2 && operators.len() < 2 {
            return Err(format!("the providers that agree on chain {id} are one operator ({})", agreeing[0].operator));
        }
        if let Some(expected) = &self.expected {
            if expected != id {
                return Err(format!("the providers serve chain {id}; the config names {expected}"));
            }
        }
        Ok(id.to_string())
    }
}

async fn evm_identity(rpc: &JsonRpc) -> Result<String> {
    let v = rpc.call("eth_chainId", json!([])).await?;
    Ok(format!("eip155:{}", crate::rpc::quantity(&v)?))
}

async fn solana_identity(rpc: &JsonRpc) -> Result<String> {
    let v = rpc.call("getGenesisHash", json!([])).await?;
    Ok(format!("solana:{}", v.as_str().ok_or_else(|| anyhow!("getGenesisHash: not a string"))?))
}

async fn rand_identity(rpc: &JsonRpc) -> Result<String> {
    let id = crate::sources::rand::chain_id(rpc).await?;
    let genesis = crate::sources::rand::genesis_hash(rpc).await?;
    Ok(format!("rand:{id}:{}", hex::encode(genesis)))
}

fn answer(url: &str, identity: Result<String>) -> Answer {
    Answer {
        shown: JsonRpc::new(url).shown(),
        operator: operator_of(url),
        identity: identity.map_err(|e| format!("{e:#}")),
    }
}

/// Asks every configured provider of every watched chain which chain it
/// serves. One read-only call per provider (two for Rand).
pub async fn probe(config: &Config) -> Vec<ChainReport> {
    let mut out = Vec::new();
    {
        let (urls, quorum) = config.rand.providers();
        let mut answers = Vec::new();
        for u in &urls {
            answers.push(answer(u, rand_identity(&JsonRpc::new(u)).await));
        }
        let expected = match (config.rand.chain_id, config.rand.genesis().ok().flatten()) {
            (Some(id), Some(g)) => Some(format!("rand:{id}:{}", hex::encode(g))),
            _ => None,
        };
        out.push(ChainReport { name: "rand".into(), quorum, answers, expected });
    }
    for e in &config.evm {
        let (urls, quorum) = e.providers();
        let mut answers = Vec::new();
        for u in &urls {
            let url = match e.kind {
                EvmKind::Evm => u.clone(),
                EvmKind::Tron => format!("{}/jsonrpc", u.trim_end_matches('/')),
            };
            answers.push(answer(u, evm_identity(&JsonRpc::new(&url)).await));
        }
        out.push(ChainReport { name: e.name.clone(), quorum, answers, expected: None });
    }
    if let Some(s) = &config.solana {
        let (urls, quorum) = s.providers();
        let mut answers = Vec::new();
        for u in &urls {
            answers.push(answer(u, solana_identity(&JsonRpc::new(u)).await));
        }
        out.push(ChainReport { name: "solana".into(), quorum, answers, expected: None });
    }
    out
}

/// The well-known public networks, to say in the report which one a chain is.
pub fn network_name(identity: &str) -> Option<&'static str> {
    match identity {
        "eip155:1" => Some("Ethereum mainnet"),
        "eip155:56" => Some("BNB Smart Chain mainnet"),
        "eip155:728126428" => Some("Tron mainnet"),
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d" => Some("Solana mainnet-beta"),
        _ => None,
    }
}

/// The report as text, and whether every chain passed.
pub fn render(reports: &[ChainReport]) -> (String, bool) {
    let mut text = String::new();
    let mut ok = true;
    for r in reports {
        text.push_str(&format!("== {} ({} of {} must agree) ==\n", r.name, r.quorum, r.answers.len()));
        for a in &r.answers {
            let said = match &a.identity {
                Ok(id) => id.clone(),
                Err(e) => format!("no answer: {e}"),
            };
            text.push_str(&format!("  {:<40} operator {:<28} {said}\n", a.shown, a.operator));
        }
        match r.verdict() {
            Ok(id) => {
                let named = network_name(&id).map(|n| format!(" ({n})")).unwrap_or_default();
                let single = if r.quorum < 2 {
                    "; a quorum of 1: a single provider can get a message signed (BR-4)"
                } else {
                    ""
                };
                text.push_str(&format!("  PASS: chain {id}{named}{single}\n"));
            }
            Err(why) => {
                ok = false;
                text.push_str(&format!("  FAIL: {why}\n"));
            }
        }
    }
    (text, ok)
}
