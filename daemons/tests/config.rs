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
