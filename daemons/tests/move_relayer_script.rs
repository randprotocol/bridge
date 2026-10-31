//! BR-16: `mainnet/move-relayer-to-droplet.sh` against stubbed ssh, rsync, pgrep, pkill and sleep on
//! PATH. Nothing here touches a real host.
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

struct Rig {
    dir: tempfile::TempDir,
}

fn write_exec(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

impl Rig {
    fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mainnet = env!("CARGO_MANIFEST_DIR").to_string() + "/mainnet";
        let script = fs::read_to_string(mainnet.clone() + "/move-relayer-to-droplet.sh").unwrap();
        write_exec(&root.join("daemons/mainnet/move-relayer-to-droplet.sh"), &script);
        fs::copy(mainnet + "/relayer.toml", root.join("daemons/mainnet/relayer.toml")).unwrap();
        // the stubbed run-relayer.sh and the log every stub appends to
        write_exec(&root.join("daemons/mainnet/run-relayer.sh"), "#!/bin/sh\necho \"run-relayer.sh\" >> \"$STUB_LOG\"\n");
        fs::create_dir_all(root.join("daemons/data/mainnet/relayer")).unwrap();
        let home = root.join("home");
        fs::create_dir_all(home.join(".rand-bridge/relayer-host")).unwrap();
        fs::write(home.join(".rand-bridge/relayer-host/host.txt"), "public 192.0.2.7\n").unwrap();
        fs::create_dir_all(home.join(".rand-chain14/wallets")).unwrap();
        fs::write(home.join(".rand-chain14/wallets/relayer.key.json"), "{}").unwrap();
        fs::write(home.join(".rand-chain14/wallets/relayer.key.json.notes.json"), "{}").unwrap();
        fs::write(
            home.join(".zshrc"),
            "export ETH_PRIVATE_KEY=aa\nexport TRON_PRIVATE_KEY=bb\nexport SOL_PRIVATE_KEY=cc\n",
        )
        .unwrap();
        let bin = root.join("bin");
        // ssh: logs the remote command (last argument), drains stdin, answers the is-active check
        // with $STUB_STATE, and exits 255 (all commands) or 1 (commands containing $STUB_FAIL).
        write_exec(
            &bin.join("ssh"),
            r#"#!/bin/sh
for last; do :; done
echo "ssh $last" >> "$STUB_LOG"
cat > /dev/null < /dev/stdin 2>/dev/null || true
[ -n "$STUB_SSH_DOWN" ] && exit 255
if [ -n "$STUB_FAIL" ]; then case "$last" in *"$STUB_FAIL"*) exit 1 ;; esac; fi
case "$last" in "systemctl is-active rand-relayer"*) echo "${STUB_STATE:-inactive}" ;; esac
exit 0
"#,
        );
        write_exec(&bin.join("rsync"), "#!/bin/sh\necho \"rsync $*\" >> \"$STUB_LOG\"\n");
        write_exec(&bin.join("pkill"), "#!/bin/sh\necho \"pkill $*\" >> \"$STUB_LOG\"\n");
        write_exec(&bin.join("pgrep"), "#!/bin/sh\nexit 1\n");
        write_exec(&bin.join("sleep"), "#!/bin/sh\nexit 0\n");
        Rig { dir }
    }

    /// Runs `move-relayer-to-droplet.sh <step> --yes`; returns (success, stderr, stub log).
    fn run(&self, step: &str, env: &[(&str, &str)]) -> (bool, String, String) {
        let root = self.dir.path();
        let log = root.join("stub.log");
        let _ = fs::remove_file(&log);
        let path = format!("{}:{}", root.join("bin").display(), std::env::var("PATH").unwrap());
        let out = Command::new("bash")
            .arg(root.join("daemons/mainnet/move-relayer-to-droplet.sh"))
            .args([step, "--yes"])
            .env("PATH", path)
            .env("HOME", root.join("home"))
            .env("STUB_LOG", &log)
            .envs(env.iter().copied())
            .output()
            .unwrap();
        let log = fs::read_to_string(&log).unwrap_or_default();
        (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned(), log)
    }
}

#[test]
fn move_stops_before_touching_anything_when_the_droplet_is_unreachable() {
    let rig = Rig::new();
    let (ok, err, log) = rig.run("move", &[("STUB_SSH_DOWN", "1")]);
    assert!(!ok, "move must fail when ssh to the droplet fails");
    assert!(err.contains("unknown"), "stderr: {err}");
    assert!(!log.contains("pkill"), "the laptop relayer was stopped:\n{log}");
    assert!(!log.contains("rsync"), "rsync ran:\n{log}");
}

#[test]
fn move_refuses_while_the_droplet_relayer_is_active() {
    let rig = Rig::new();
    let (ok, err, log) = rig.run("move", &[("STUB_STATE", "active")]);
    assert!(!ok);
    assert!(err.contains("already running"), "stderr: {err}");
    assert!(!log.contains("pkill") && !log.contains("rsync"), "{log}");
}

#[test]
fn move_proceeds_when_the_droplet_reports_inactive() {
    let rig = Rig::new();
    let (ok, err, log) = rig.run("move", &[("STUB_STATE", "inactive")]);
    assert!(ok, "stderr: {err}\n{log}");
    assert!(log.contains("pkill") && log.contains("rsync"), "{log}");
}

#[test]
fn back_removes_the_env_file_and_wallet_from_the_droplet_after_copying_back() {
    let rig = Rig::new();
    let (ok, err, log) = rig.run("back", &[]);
    assert!(ok, "stderr: {err}\n{log}");
    let at = |needle: &str| log.lines().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("no {needle}:\n{log}"));
    let notes = at("rsync -a -e");
    let notes = log.lines().enumerate().filter(|(_, l)| l.contains("notes.json")).map(|(i, _)| i).next().unwrap_or(notes);
    let rm = at("/etc/rand-relayer/env");
    assert!(log.lines().nth(rm).unwrap().contains("/var/lib/rand-relayer/wallet"), "{log}");
    assert!(notes < rm, "the notes must be copied back before the wallet is removed:\n{log}");
    assert!(rm < at("run-relayer.sh"), "the laptop relayer starts only after the removal:\n{log}");
}

#[test]
fn back_does_not_start_the_laptop_relayer_if_the_removal_or_the_stop_fails() {
    for fail in ["rm -f", "disable -q --now"] {
        let rig = Rig::new();
        let (ok, _err, log) = rig.run("back", &[("STUB_FAIL", fail)]);
        assert!(!ok, "back must fail when `{fail}` fails on the droplet");
        assert!(!log.contains("run-relayer.sh"), "{fail}: the laptop relayer started:\n{log}");
    }
}
