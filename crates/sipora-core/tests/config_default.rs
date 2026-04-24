use sipora_core::config::SiporaConfig;

#[test]
fn sipora_config_deserializes_empty_builder() {
    let c: SiporaConfig = config::Config::builder()
        .build()
        .expect("builder")
        .try_deserialize()
        .expect("empty config should deserialize to defaults");
    assert_eq!(c.redis.nodes, vec!["redis://127.0.0.1:6379".to_string()]);
    assert_eq!(c.postgres.url, "postgres://127.0.0.1:5432/sipora");
    assert_eq!(c.b2bua.downstream.as_deref(), Some("127.0.0.1:5070"));
}

#[test]
fn sipora_config_default_matches_empty_deserialize() {
    let from_default = SiporaConfig::default();
    let from_empty: SiporaConfig = config::Config::builder()
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(from_default.general.domain, from_empty.general.domain);
    assert_eq!(from_default.redis.nodes, from_empty.redis.nodes);
}
