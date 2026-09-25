use bridge_daemons::config::Config;

#[test]
fn the_example_config_parses_and_yields_an_emitter_per_chain() {
    let path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml"));
    let config = Config::load(path).expect("config.example.toml");
    assert!(config.guardian.is_some() && config.relayer.is_some());
    let emitters = config.emitters().unwrap();
    let mut chains: Vec<u16> = emitters.endpoints.iter().map(|(c, _)| *c).collect();
    chains.sort_unstable();
    assert_eq!(chains, vec![2, 3, 4, 5]);
}

const MINIMAL: &str = r#"
data_dir = "./data"
[rand]
rpc = "http://127.0.0.1:8545"
emitter = "0000000000000000000000000000000000000000000000000000000000000000"
"#;

fn load(text: &str) -> anyhow::Result<Config> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.toml");
    std::fs::write(&path, text).unwrap();
    Config::load(&path)
}

#[test]
fn the_governance_policy_defaults_to_48h_and_2_signers() {
    let config = load(MINIMAL).unwrap();
    assert!(config.governance.is_none());
    let policy = config.governance_policy();
    assert_eq!(policy.min_delay_secs, 172_800);
    assert_eq!(policy.min_threshold, 2);
    assert_eq!(policy.solana_multisig, None);
    assert_eq!(policy.solana_vault_index, 0);

    let config = load(&format!("{MINIMAL}\n[governance]\nmin_threshold = 3\n")).unwrap();
    let policy = config.governance_policy();
    assert_eq!((policy.min_delay_secs, policy.min_threshold), (172_800, 3));
}

#[test]
fn the_governance_section_is_read_and_checked() {
    let config = load(&format!(
        "{MINIMAL}\n[governance]\nmin_delay_secs = 86400\nmin_threshold = 3\n\
         solana_multisig = \"5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6\"\nsolana_vault_index = 1\n"
    ))
    .unwrap();
    let policy = config.governance_policy();
    assert_eq!(policy.min_delay_secs, 86_400);
    assert_eq!(policy.min_threshold, 3);
    assert_eq!(
        policy.solana_multisig.as_deref(),
        Some("5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6")
    );
    assert_eq!(policy.solana_vault_index, 1);

    assert!(load(&format!(
        "{MINIMAL}\n[governance]\nsolana_multisig = \"not-base58-0OIl\"\n"
    ))
    .is_err());
    assert!(load(&format!("{MINIMAL}\n[governance]\nmin_threshold = 0\n")).is_err());
    assert!(
        load(&format!("{MINIMAL}\n[governance]\nmin_delay = 1\n")).is_err(),
        "unknown keys are refused"
    );
}

#[test]
fn the_mainnet_configs_still_parse() {
    for name in ["relayer", "guardian-1"] {
        let path = std::path::PathBuf::from(format!(
            "{}/mainnet/{name}.toml",
            env!("CARGO_MANIFEST_DIR")
        ));
        Config::load(&path).unwrap_or_else(|e| panic!("{name}: {e:#}"));
    }
}
