//! BR-402: `mainnet/provision-guardian.sh` under `--root <tempdir>`. Nothing here touches a
//! real host, a real key or systemd.
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use sha2::{Digest, Sha256};

fn script() -> String {
    env!("CARGO_MANIFEST_DIR").to_string() + "/mainnet/provision-guardian.sh"
}

struct Rig {
    dir: tempfile::TempDir,
    sha: String,
}

impl Rig {
    fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let binary = b"#!/bin/sh\necho not a real guardian\n";
        fs::write(dir.path().join("rand-guardian"), binary).unwrap();
        let config = fs::read_to_string(env!("CARGO_MANIFEST_DIR").to_string() + "/mainnet/guardian-7.toml").unwrap();
        fs::write(dir.path().join("guardian-7.toml"), config).unwrap();
        Rig { sha: hex::encode(Sha256::digest(binary)), dir }
    }
    fn root(&self) -> std::path::PathBuf {
        self.dir.path().join("root")
    }
    fn run(&self, index: &str, sha: &str, config: &Path, extra: &[&str]) -> (bool, String, String) {
        let o = Command::new("bash")
            .arg(script())
            .args(["--index", index, "--sha256", sha, "--binary"])
            .arg(self.dir.path().join("rand-guardian"))
            .arg("--config")
            .arg(config)
            .arg("--root")
            .arg(self.root())
            .args(extra)
            .output()
            .unwrap();
        (o.status.success(), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
    }
    fn cfg(&self) -> std::path::PathBuf {
        self.dir.path().join("guardian-7.toml")
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn it_lays_the_guardian_down_without_keys_and_without_starting_it() {
    let rig = Rig::new();
    let (ok, out, err) = rig.run("7", &rig.sha, &rig.cfg(), &["--dry-run"]);
    assert!(ok && out.contains("dry run: nothing written"), "{out}\n{err}");
    assert!(!rig.root().exists());

    let (ok, out, err) = rig.run("7", &rig.sha, &rig.cfg(), &[]);
    assert!(ok, "{out}\n{err}");
    let root = rig.root();
    assert_eq!(mode(&root.join("usr/local/bin/rand-guardian")), 0o755);
    assert_eq!(mode(&root.join("etc/rand-guardian.toml")), 0o640);
    let env_path = root.join("etc/rand-guardian/env");
    assert_eq!(mode(&env_path), 0o600);
    let env = fs::read_to_string(&env_path).unwrap();
    assert!(env.contains("\nGUARDIAN7_PRIV_KEY=\n") && env.contains("\nGUARDIAN7_PQ_SEED=\n"), "names only, no values: {env}");
    let unit = fs::read_to_string(root.join("etc/systemd/system/rand-guardian.service")).unwrap();
    assert!(unit.contains("EnvironmentFile=/etc/rand-guardian/env") && unit.contains("User=rand-guardian"), "{unit}");
    assert!(root.join("var/lib/rand-guardian/data").is_dir());
    assert!(out.contains("the service is NOT started") && out.contains("--headroom"), "{out}");

    // Run again: nothing differs, and a secrets file someone filled is left alone.
    fs::write(&env_path, "GUARDIAN7_PRIV_KEY=filled-by-the-holder\n").unwrap();
    let (ok, out, err) = rig.run("7", &rig.sha, &rig.cfg(), &[]);
    assert!(ok, "{out}\n{err}");
    assert_eq!(fs::read_to_string(&env_path).unwrap(), "GUARDIAN7_PRIV_KEY=filled-by-the-holder\n");
    assert!(!out.contains("filled-by-the-holder") && !err.contains("filled-by-the-holder"), "the secrets file is never read out");
}

#[test]
fn it_refuses_a_wrong_checksum_another_guardians_config_and_an_overwrite() {
    let rig = Rig::new();
    let (ok, _, err) = rig.run("7", &"0".repeat(64), &rig.cfg(), &[]);
    assert!(!ok && err.contains("do not install it"), "{err}");
    assert!(!rig.root().exists(), "nothing is written after a refusal");

    let (ok, _, err) = rig.run("8", &rig.sha, &rig.cfg(), &[]);
    assert!(!ok && err.contains("GUARDIAN8_PRIV_KEY"), "{err}");

    // A config that listens beyond loopback, or carries a key, is refused.
    let open = rig.dir.path().join("open.toml");
    fs::write(&open, fs::read_to_string(rig.cfg()).unwrap().replace("listen = \"127.0.0.1:", "listen = \"0.0.0.0:")).unwrap();
    let (ok, _, err) = rig.run("7", &rig.sha, &open, &[]);
    assert!(!ok && err.contains("127.0.0.1"), "{err}");
    let keyed = rig.dir.path().join("keyed.toml");
    fs::write(&keyed, format!("{}\npriv_key = \"{}\"\n", fs::read_to_string(rig.cfg()).unwrap(), "ab".repeat(32))).unwrap();
    let (ok, _, err) = rig.run("7", &rig.sha, &keyed, &[]);
    assert!(!ok && err.contains("key material"), "{err}");

    // Installed once; a different config afterwards does not replace it.
    assert!(rig.run("7", &rig.sha, &rig.cfg(), &[]).0);
    let other = rig.dir.path().join("other.toml");
    fs::write(&other, fs::read_to_string(rig.cfg()).unwrap() + "\n# changed\n").unwrap();
    let (ok, _, err) = rig.run("7", &rig.sha, &other, &[]);
    assert!(!ok && err.contains("does not overwrite"), "{err}");
}

#[test]
fn the_headroom_units_run_the_read_only_check() {
    let dir = env!("CARGO_MANIFEST_DIR").to_string() + "/mainnet/systemd/";
    let service = fs::read_to_string(dir.clone() + "rand-bridge-headroom.service").unwrap();
    assert!(service.contains("rand-bridge-audit --config /etc/rand-relayer.toml --headroom --min-spare 1"), "{service}");
    assert!(service.contains("OnFailure="), "a failed check tells someone");
    assert!(fs::read_to_string(dir + "rand-bridge-headroom.timer").unwrap().contains("OnUnitActiveSec=5min"));
}
