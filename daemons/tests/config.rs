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

#[test]
fn the_governance_policy_has_floors() {
    // The deploy script refuses a delay under 24 h; the audit refuses a laxer policy.
    assert!(load(&format!("{MINIMAL}\n[governance]\nmin_delay_secs = 86399\n")).is_err());
    assert!(load(&format!("{MINIMAL}\n[governance]\nmin_delay_secs = 86400\n")).is_ok());
    assert!(load(&format!("{MINIMAL}\n[governance]\nmin_threshold = 1\n")).is_err());
}

#[test]
fn the_governance_section_names_the_timelock_and_admin_multisig_per_chain() {
    let config = load(&format!(
        "{MINIMAL}\n[governance]\n\
         timelock_deploy_block = {{ 2 = 26100000, 3 = 123000000, 4 = 86500000 }}\n\
         admin_multisig = {{ 2 = \"0x1111111111111111111111111111111111111111\", \
         3 = \"0x2222222222222222222222222222222222222222\", \
         4 = \"TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU\" }}\n"
    ))
    .unwrap();
    let policy = config.governance_policy();
    assert_eq!(policy.deploy_block(2), Some(26_100_000));
    assert_eq!(policy.deploy_block(4), Some(86_500_000));
    assert_eq!(policy.deploy_block(5), None);
    assert_eq!(policy.admin_multisig20(2).unwrap(), Some([0x11; 20]));
    // A Tron multisig may be given in its T… form.
    assert_eq!(
        policy.admin_multisig20(4).unwrap().map(hex::encode).as_deref(),
        Some("0992df85dcce77ded2c0387f1fa9cf98ac859700")
    );
    assert_eq!(config.governance_policy().admin_multisig20(5).unwrap(), None);
    // Unset, both tables are empty.
    let empty = load(MINIMAL).unwrap().governance_policy();
    assert_eq!((empty.deploy_block(2), empty.admin_multisig20(2).unwrap()), (None, None));

    for bad in [
        "timelock_deploy_block = { 7 = 1 }",
        "timelock_deploy_block = { eth = 1 }",
        "admin_multisig = { 2 = \"0x11\" }",
        "admin_multisig = { 2 = \"TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU\" }",
        "admin_multisig = { 4 = \"TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkV\" }",
        "admin_multisig = { 6 = \"0x1111111111111111111111111111111111111111\" }",
    ] {
        assert!(
            load(&format!("{MINIMAL}\n[governance]\n{bad}\n")).is_err(),
            "{bad} must be refused"
        );
    }
}
