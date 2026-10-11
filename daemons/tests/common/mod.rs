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
pub fn rpc(
    methods: impl Fn(&str, &Value) -> Option<Result<Value, Value>> + Send + Sync + 'static,
) -> Fake {
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
    let bytes = hex::decode(if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    })
    .unwrap();
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

pub fn transfer(
    amount: u128,
    fee: u128,
    token_chain: u16,
    to_chain: u16,
    to: [u8; 32],
) -> Transfer {
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
        transfer(
            amount,
            fee,
            to_chain,
            to_chain,
            word("0x000000000000000000000000000000000000cafe"),
        ),
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

// ---- subprocess helpers ------------------------------------------------------

/// Only for an address nothing is meant to answer on. A daemon that must bind a port goes
/// through `start_daemon`, which retries when the port was taken in between.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn pad32(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.resize(v.len().div_ceil(32) * 32, 0);
    v
}

/// A `MessagePublished(uint64 indexed sequence, uint32 nonce, uint8 level, bytes payload)` log
/// of `contract`, carrying the payload of `body`.
pub fn evm_log(contract: &str, observed: &Observed, block: u64) -> Value {
    let body = observed.decoded();
    let mut data = Vec::new();
    data.extend_from_slice(&word(&format!("{:x}", body.nonce)));
    data.extend_from_slice(&word(&format!("{:x}", body.consistency_level)));
    data.extend_from_slice(&word("60"));
    data.extend_from_slice(&word(&format!("{:x}", body.payload.len())));
    data.extend_from_slice(&pad32(&body.payload));
    json!({
        "address": contract,
        "topics": ["0xabcd", format!("0x{}", hex::encode(word(&format!("{:x}", body.sequence))))],
        "data": format!("0x{}", hex::encode(data)),
        "blockNumber": format!("0x{block:x}"),
        "removed": false,
    })
}

/// A running daemon: stdout and stderr go to files, `stop` interrupts it the way an
/// operator would and returns its exit status.
pub struct Daemon {
    child: std::process::Child,
    pub log: std::path::PathBuf,
}

impl Daemon {
    pub fn spawn(mut command: std::process::Command, dir: &std::path::Path) -> Daemon {
        let log = dir.join("daemon.log");
        let file = std::fs::File::create(&log).unwrap();
        command
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .env("NO_COLOR", "1");
        Daemon {
            child: command.spawn().unwrap(),
            log,
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Whether it already exited (a startup error), with its status.
    pub fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().unwrap()
    }

    /// SIGINT, then wait (at most 20 s) for a clean exit.
    pub fn stop(mut self) -> std::process::ExitStatus {
        let _ = std::process::Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        for _ in 0..200 {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = self.child.kill();
        panic!("daemon did not stop on SIGINT:\n{}", self.log());
    }

    pub fn wait(mut self) -> std::process::ExitStatus {
        for _ in 0..200 {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = self.child.kill();
        panic!("daemon did not exit:\n{}", self.log());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Polls `check` every 100 ms for up to 30 s.
pub fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..300 {
        if check() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

/// A blocking HTTP/1.1 request over a plain socket: `(status, body)`, or `None` when
/// nothing answers. Enough for polling a daemon's API without a blocking client.
pub fn request(method: &str, url: &str, content_type: &str, body: &str) -> Option<(u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (host, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let mut stream = TcpStream::connect(host).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let status = raw.split_whitespace().nth(1)?.parse().ok()?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Some((status, body))
}

pub fn get_json(url: &str) -> Option<(u16, Value)> {
    let (status, body) = request("GET", url, "application/json", "")?;
    Some((status, serde_json::from_str(&body).unwrap_or(Value::Null)))
}

/// Writes an executable `#!/bin/sh` script that is safe to exec at once.
///
/// Exec of a file that some other thread still holds open for writing fails with ETXTBSY
/// ("text file busy"): another test thread that forked while the file was open keeps the
/// descriptor until its own exec. So the script is written under a temporary name, synced and
/// closed, renamed into place, and then exec'd once with `--etxtbsy-probe` (which every script
/// answers by exiting 0) until the exec succeeds. After the descriptor is closed no new fork can
/// inherit it, so once the probe has run, whoever execs the script next cannot hit ETXTBSY.
pub fn write_script(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut file = std::fs::File::create(&tmp).unwrap();
        write!(
            file,
            "#!/bin/sh\n[ \"$1\" = --etxtbsy-probe ] && exit 0\n{body}\n"
        )
        .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o755))
            .unwrap();
        file.sync_all().unwrap();
    }
    std::fs::rename(&tmp, path).unwrap();
    for _ in 0..500 {
        match std::process::Command::new(path)
            .arg("--etxtbsy-probe")
            .status()
        {
            Ok(status) => {
                assert!(status.success());
                return;
            }
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(e) => panic!("cannot exec {}: {e}", path.display()),
        }
    }
    panic!("{} stayed busy", path.display());
}

/// Starts a daemon that listens on a port of its own choosing from `launch(port)`, retrying
/// with a fresh port when the daemon lost the race for it ("binding" in its log).
pub fn start_daemon(
    dir: &std::path::Path,
    launch: impl Fn(u16) -> std::process::Command,
) -> (Daemon, u16) {
    for _ in 0..10 {
        let port = free_port();
        let mut daemon = Daemon::spawn(launch(port), dir);
        let mut listening = false;
        for _ in 0..300 {
            if daemon.exited().is_some() {
                break;
            }
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                // A daemon that lost the race exits at once; give it a moment to do so.
                std::thread::sleep(std::time::Duration::from_millis(300));
                listening = daemon.exited().is_none();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if listening {
            return (daemon, port);
        }
        let log = daemon.log();
        assert!(log.contains("binding"), "daemon failed to start:\n{log}");
        drop(daemon);
    }
    panic!("no free port after 10 attempts");
}
