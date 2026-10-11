//! Loopback fakes shared by the integration tests: a tiny HTTP/1.1 server that
//! answers from a closure, and builders for the messages the daemons handle.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use bridge_codec::{Body, Payload, Transfer};
use bridge_daemons::message::Observed;
use serde_json::{json, Value};

/// One request the fake saw: method, path, parsed JSON body (`Null` for none).
#[derive(Clone, Debug)]
pub struct Seen {
    pub http_method: String,
    pub path: String,
    pub body: Value,
}

impl Seen {
    /// The JSON-RPC method of a request, if it is one.
    pub fn rpc_method(&self) -> Option<&str> {
        self.body["method"].as_str()
    }
}

pub struct Fake {
    pub url: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn rpc_methods(&self) -> Vec<String> {
        self.requests()
            .iter()
            .filter_map(|s| s.rpc_method().map(str::to_string))
            .collect()
    }

    pub fn count(&self, method: &str) -> usize {
        self.rpc_methods().iter().filter(|m| *m == method).count()
    }
}

/// `(status, body)` for a request; `handler(seen)` decides.
pub type Reply = (u16, String);

/// Serves `handler` on a loopback port, one thread per connection, until the
/// test process ends.
pub fn http(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(handler);
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (handler, log) = (handler.clone(), log.clone());
            std::thread::spawn(move || serve(stream, handler.as_ref(), &log));
        }
    });
    Fake { url, seen }
}

fn serve(mut stream: TcpStream, handler: &dyn Fn(&Seen) -> Reply, log: &Mutex<Vec<Seen>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    let (http_method, path) = (
        first.next().unwrap_or_default().to_string(),
        first.next().unwrap_or_default().to_string(),
    );
    let length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while buf.len() < header_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = serde_json::from_slice(&buf[header_end..header_end + length]).unwrap_or(Value::Null);
    let seen = Seen {
        http_method,
        path,
        body,
    };
    log.lock().unwrap().push(seen.clone());
    let (status, text) = handler(&seen);
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// A JSON-RPC 2.0 node: `methods(method, params)` returns the result, or the
/// error object. Anything it declines (`None`) is a method-not-found error.
pub fn rpc(methods: impl Fn(&str, &Value) -> Option<Result<Value, Value>> + Send + Sync + 'static) -> Fake {
    http(move |seen| {
        let method = seen.body["method"].as_str().unwrap_or_default();
        let reply = match methods(method, &seen.body["params"]) {
            Some(Ok(result)) => json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
            Some(Err(error)) => json!({ "jsonrpc": "2.0", "id": 1, "error": error }),
            None => {
                json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "method not found" } })
            }
        };
        (200, reply.to_string())
    })
}

pub fn word(addr: &str) -> [u8; 32] {
    let mut w = [0u8; 32];
    let digits = addr.trim_start_matches("0x");
    let bytes = hex::decode(if digits.len() % 2 == 1 { format!("0{digits}") } else { digits.to_string() }).unwrap();
    w[32 - bytes.len()..].copy_from_slice(&bytes);
    w
}

pub const RAND_EMITTER: [u8; 32] = [0xAA; 32];

pub fn transfer_body(
    emitter_chain: u16,
    emitter: [u8; 32],
    sequence: u64,
    transfer: Transfer,
) -> Vec<u8> {
    Body {
        timestamp: 1_800_000_000,
        nonce: 3,
        emitter_chain,
        emitter_address: emitter,
        sequence,
        consistency_level: 1,
        payload: Payload::Transfer(transfer).encode(),
    }
    .encode()
}

pub fn transfer(amount: u128, fee: u128, token_chain: u16, to_chain: u16, to: [u8; 32]) -> Transfer {
    Transfer {
        amount: Transfer::u256_from_u128(amount),
        token_address: word("0x00000000000000000000000000000000000000dd"),
        token_chain,
        to,
        to_chain,
        fee: Transfer::u256_from_u128(fee),
    }
}

/// A burn on Rand (chain 1) released on `to_chain`.
pub fn burn(sequence: u64, to_chain: u16, amount: u128, fee: u128) -> Observed {
    Observed::new(transfer_body(
        1,
        RAND_EMITTER,
        sequence,
        transfer(amount, fee, to_chain, to_chain, word("0x000000000000000000000000000000000000cafe")),
    ))
    .unwrap()
}

/// A lock on an EVM chain, minted on Rand to `to`.
pub fn lock(chain: u16, emitter: [u8; 32], sequence: u64, to: [u8; 32]) -> Observed {
    Observed::new(transfer_body(
        chain,
        emitter,
        sequence,
        transfer(100_000_000, 0, chain, 1, to),
    ))
    .unwrap()
}

pub fn guardian_keys(n: u8) -> Vec<bridge_daemons::crypto::GuardianKey> {
    (1..=n)
        .map(|i| bridge_daemons::crypto::GuardianKey::from_hex(&format!("{i:064x}")).unwrap())
        .collect()
}
