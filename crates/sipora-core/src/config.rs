use serde::Deserialize;
use std::path::Path;

/// Full stack config: every field has a default so [`SiporaConfig::load`](SiporaConfig::load) works with no file.
/// Use [`load_from_config_input`](SiporaConfig::load_from_config_input) with `--config` / `SIPORA_CONFIG` for other stems or paths.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SiporaConfig {
    pub general: GeneralConfig,
    pub upstreams: UpstreamsConfig,
    pub tls: TlsConfig,
    pub rate_limit: RateLimitConfig,
    pub registrar: RegistrarConfig,
    pub proxy: ProxyConfig,
    pub auth: AuthConfig,
    pub redis: RedisConfig,
    pub postgres: PostgresConfig,
    pub telemetry: TelemetryConfig,
    pub media: MediaConfig,
    pub kafka: KafkaConfig,
    pub b2bua: B2buaConfig,
    pub stir: StirConfig,
    pub transport: TransportConfig,
    pub push: PushConfig,
}

/// B2BUA: back-to-back SIP signaling toward a downstream peer (B-leg).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct B2buaConfig {
    /// `host:port` of the downstream SIP peer (defaults to local lab target).
    pub downstream: Option<String>,
}

impl Default for B2buaConfig {
    fn default() -> Self {
        // Must not equal `general.sip_udp_port` (5060): forwarding INVITE to the same
        // UDP port loops back into this process and breaks SIPp/clients (unexpected INVITE).
        Self {
            downstream: Some("127.0.0.1:5070".into()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    #[serde(default = "default_sip_domain")]
    pub domain: String,
    /// Host or IP placed in the top `Via` when the proxy forwards SIP (must match what clients use).
    #[serde(default)]
    pub sip_advertised_host: Option<String>,
    /// Plain SIP UDP port (RFC 3261 default 5060).
    #[serde(default = "default_sip_udp_port")]
    pub sip_udp_port: u16,
    #[serde(default = "default_sips_port")]
    pub sips_port: u16,
    #[serde(default = "default_wss_port")]
    pub wss_port: u16,
    #[serde(default = "default_outbound_port")]
    pub outbound_port: u16,
    #[serde(default = "default_health_port")]
    pub health_port: u16,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            domain: default_sip_domain(),
            sip_advertised_host: None,
            sip_udp_port: default_sip_udp_port(),
            sips_port: default_sips_port(),
            wss_port: default_wss_port(),
            outbound_port: default_outbound_port(),
            health_port: default_health_port(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,
    #[serde(default)]
    pub mtls_trunks: bool,
    #[serde(default = "default_true")]
    pub ocsp_staple: bool,
    #[serde(default = "default_cert_renew_threshold")]
    pub cert_renew_threshold: f64,
    #[serde(default = "default_acme_provider")]
    pub acme_provider: String,
    /// PEM paths for inbound TLS (edge). When unset, edge may use plain TCP for lab setups.
    #[serde(default)]
    pub listen_cert_pem_path: Option<String>,
    #[serde(default)]
    pub listen_key_pem_path: Option<String>,
    /// Optional PEM file of CA certs for verifying client certificates (mTLS).
    #[serde(default)]
    pub mtls_client_ca_pem_path: Option<String>,
    /// Optional DER file with a stapled OCSP response (from your CA or `openssl ocsp`).
    #[serde(default)]
    pub ocsp_response_der_path: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: default_tls_min_version(),
            mtls_trunks: false,
            ocsp_staple: default_true(),
            cert_renew_threshold: default_cert_renew_threshold(),
            acme_provider: default_acme_provider(),
            listen_cert_pem_path: None,
            listen_key_pem_path: None,
            mtls_client_ca_pem_path: None,
            ocsp_response_der_path: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    #[serde(default = "default_register_rate")]
    pub register_rate: u32,
    #[serde(default = "default_invite_rate")]
    pub invite_rate: u32,
    #[serde(default = "default_dialog_rate")]
    pub dialog_rate: u32,
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u32,
    #[serde(default = "default_block_window_s")]
    pub block_window_s: u64,
    #[serde(default = "default_block_cooldown_s")]
    pub block_cooldown_s: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            register_rate: default_register_rate(),
            invite_rate: default_invite_rate(),
            dialog_rate: default_dialog_rate(),
            block_threshold: default_block_threshold(),
            block_window_s: default_block_window_s(),
            block_cooldown_s: default_block_cooldown_s(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RegistrarConfig {
    #[serde(default = "default_min_expires")]
    pub min_expires: u32,
    #[serde(default = "default_max_expires")]
    pub max_expires: u32,
    #[serde(default = "default_default_expires")]
    pub default_expires: u32,
    #[serde(default = "default_nonce_ttl_s")]
    pub nonce_ttl_s: u64,
    /// Optional outbound edge URI for Service-Route / Path scenarios (labs).
    #[serde(default)]
    pub outbound_edge_uri: Option<String>,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            min_expires: default_min_expires(),
            max_expires: default_max_expires(),
            default_expires: default_default_expires(),
            nonce_ttl_s: default_nonce_ttl_s(),
            outbound_edge_uri: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

fn default_max_message_bytes() -> usize {
    65535
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PushConfig {
    #[serde(default)]
    pub fcm_credentials_path: Option<String>,
    #[serde(default)]
    pub apns_topic: Option<String>,
    /// Generic push gateway URL (HTTPS). When unset, `wake_device` is not used.
    #[serde(default)]
    pub gateway_url: Option<String>,
    #[serde(default = "default_push_timeout_ms")]
    pub timeout_ms: u64,
    /// Name of an environment variable holding a bearer token for the gateway.
    #[serde(default)]
    pub auth_bearer_env: Option<String>,
    /// Treat bindings with push params as idle if last REGISTER older than this (seconds).
    #[serde(default = "default_push_device_idle_secs")]
    pub device_idle_secs: u64,
}

fn default_push_timeout_ms() -> u64 {
    5000
}

fn default_push_device_idle_secs() -> u64 {
    120
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            fcm_credentials_path: None,
            apns_topic: None,
            gateway_url: None,
            timeout_ms: default_push_timeout_ms(),
            auth_bearer_env: None,
            device_idle_secs: default_push_device_idle_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    #[serde(default = "default_max_forwards")]
    pub max_forwards: u8,
    #[serde(default = "default_true")]
    pub fork_parallel: bool,
    #[serde(default = "default_trace_header")]
    pub trace_header: String,
    #[serde(default = "default_location_timeout_ms")]
    pub location_timeout_ms: u64,
    /// SIP over WebSocket listen port on the proxy (`0` = disabled).
    #[serde(default = "default_proxy_ws_listen_port")]
    pub ws_listen_port: u16,
}

fn default_proxy_ws_listen_port() -> u16 {
    0
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            max_forwards: default_max_forwards(),
            fork_parallel: default_true(),
            trace_header: default_trace_header(),
            location_timeout_ms: default_location_timeout_ms(),
            ws_listen_port: default_proxy_ws_listen_port(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    #[serde(default = "default_nonce_ttl_s")]
    pub nonce_ttl_s: u64,
    #[serde(default = "default_nonce_len")]
    pub nonce_len: usize,
    pub jwks_url: Option<String>,
    #[serde(default = "default_auth_timeout_ms")]
    pub auth_timeout_ms: u64,
    /// Shared secret for `Authorization: Bearer` on the provisioning HTTP API (`sipora-api`).
    /// When unset, `/api/*` requests are rejected (fail closed).
    #[serde(default)]
    pub api_bearer_token: Option<String>,
    /// When set, JWT `iss` must match (use with JWKS validation).
    #[serde(default)]
    pub jwt_expected_issuer: Option<String>,
    /// When set, JWT `aud` must match. Strongly recommended for OIDC-issued tokens.
    #[serde(default)]
    pub jwt_expected_audience: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            nonce_ttl_s: default_nonce_ttl_s(),
            nonce_len: default_nonce_len(),
            jwks_url: None,
            auth_timeout_ms: default_auth_timeout_ms(),
            api_bearer_token: None,
            jwt_expected_issuer: None,
            jwt_expected_audience: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    #[serde(default = "default_redis_nodes")]
    pub nodes: Vec<String>,
    #[serde(default = "default_true")]
    pub cluster_mode: bool,
    #[serde(default = "default_max_call_s")]
    pub max_call_s: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            nodes: default_redis_nodes(),
            cluster_mode: default_true(),
            max_call_s: default_max_call_s(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PostgresConfig {
    #[serde(default = "default_postgres_url")]
    pub url: String,
    #[serde(default = "default_pool_size")]
    pub max_pool_size: u32,
    #[serde(default = "default_cdr_retention_months")]
    pub cdr_retention_months: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: default_postgres_url(),
            max_pool_size: default_pool_size(),
            cdr_retention_months: default_cdr_retention_months(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
    #[serde(default = "default_metrics_interval_s")]
    pub metrics_interval_s: u64,
    #[serde(default = "default_success_sample_rate")]
    pub success_sample_rate: f64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: default_otlp_endpoint(),
            service_name: default_service_name(),
            metrics_interval_s: default_metrics_interval_s(),
            success_sample_rate: default_success_sample_rate(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MediaConfig {
    #[serde(default = "default_rtpengine_host")]
    pub rtpengine_host: String,
    /// ICE handling for rtpengine ng `offer`/`answer` commands: `remove`, `force`, or `optional`.
    #[serde(default = "default_rtpengine_ice")]
    pub rtpengine_ice: String,
    /// DTLS mode for rtpengine ng commands: `passive` or `off`.
    #[serde(default = "default_rtpengine_dtls")]
    pub rtpengine_dtls: String,
    #[serde(default = "default_allowed_codecs")]
    pub allowed_codecs: Vec<String>,
    #[serde(default = "default_true")]
    pub srtp_required: bool,
    #[serde(default = "default_rtp_timeout_s")]
    pub rtp_timeout_s: u64,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            rtpengine_host: default_rtpengine_host(),
            rtpengine_ice: default_rtpengine_ice(),
            rtpengine_dtls: default_rtpengine_dtls(),
            allowed_codecs: default_allowed_codecs(),
            srtp_required: default_true(),
            rtp_timeout_s: default_rtp_timeout_s(),
        }
    }
}

/// STIR/SHAKEN policy for SIP INVITE Identity header verification (proxy) and PASSporT signing (B2BUA).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StirConfig {
    /// Verification mode for inbound Identity headers: "disabled" (default), "permissive", or "strict".
    #[serde(default = "default_stir_mode")]
    pub mode: String,
    /// Source IPs whose P-Asserted-Identity headers are trusted (RFC 3325 §9.1).
    /// Accepts IPv4 and IPv6 literals; CIDR notation is not supported.
    #[serde(default)]
    pub trusted_peer_ips: Vec<String>,
    /// Path to an EC (P-256) private key PEM for B2BUA outbound PASSporT signing.
    /// When absent, the B2BUA does not attach an Identity header.
    #[serde(default)]
    pub privkey_pem_path: Option<String>,
    /// Publicly-reachable HTTPS URL where the STI-AS signing certificate can be fetched.
    /// Required when `privkey_pem_path` is set.
    #[serde(default)]
    pub cert_url: Option<String>,
    /// Attestation level the B2BUA can vouch for: "A" (full), "B" (partial), "C" (gateway).
    #[serde(default = "default_attest_level")]
    pub attest: String,
    /// PEM file with one or more STI-CA / operator trust anchors for Identity cert chain
    /// validation (RFC 8226 §5). Required when `mode` is `strict`.
    #[serde(default)]
    pub trust_anchor_pem_path: Option<String>,
}

impl Default for StirConfig {
    fn default() -> Self {
        Self {
            mode: default_stir_mode(),
            trusted_peer_ips: Vec::new(),
            privkey_pem_path: None,
            cert_url: None,
            attest: default_attest_level(),
            trust_anchor_pem_path: None,
        }
    }
}

impl StirConfig {
    /// Ensures `[stir]` values are recognized, signing keys have a public cert URL, and returns a
    /// copy with `mode` and `attest` normalized (trimmed, ASCII lowercase) for callers to use
    /// without re-parsing.
    pub fn validate(&self) -> Result<StirConfig, config::ConfigError> {
        let mode = self.mode.trim().to_ascii_lowercase();
        if mode.is_empty() {
            return Err(config::ConfigError::Message(
                "[stir].mode must not be empty (allowed: disabled, permissive, strict)".into(),
            ));
        }
        if !matches!(mode.as_str(), "disabled" | "permissive" | "strict") {
            return Err(config::ConfigError::Message(format!(
                "[stir].mode={:?} is invalid (allowed: disabled, permissive, strict)",
                self.mode
            )));
        }
        let attest = self.attest.trim().to_ascii_lowercase();
        if attest.is_empty() {
            return Err(config::ConfigError::Message(
                "[stir].attest must not be empty (allowed: A, B, C)".into(),
            ));
        }
        if !matches!(attest.as_str(), "a" | "b" | "c") {
            return Err(config::ConfigError::Message(format!(
                "[stir].attest={:?} is invalid (allowed: A, B, C)",
                self.attest
            )));
        }
        if self.privkey_pem_path.is_some() && self.cert_url.is_none() {
            return Err(config::ConfigError::Message(
                "[stir].cert_url is required when [stir].privkey_pem_path is set".into(),
            ));
        }
        if mode == "strict" {
            let path = self
                .trust_anchor_pem_path
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let Some(path) = path else {
                return Err(config::ConfigError::Message(
                    "[stir].trust_anchor_pem_path is required when [stir].mode=strict".into(),
                ));
            };
            if !std::path::Path::new(path).is_file() {
                return Err(config::ConfigError::Message(format!(
                    "[stir].trust_anchor_pem_path must be an existing file (got {path:?})"
                )));
            }
        }
        Ok(StirConfig {
            mode,
            trusted_peer_ips: self.trusted_peer_ips.clone(),
            privkey_pem_path: self.privkey_pem_path.clone(),
            cert_url: self.cert_url.clone(),
            attest,
            trust_anchor_pem_path: self
                .trust_anchor_pem_path
                .as_ref()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        })
    }
}

/// Optional Kafka brokers for CDR export. Empty `brokers` disables publishing.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct KafkaConfig {
    #[serde(default)]
    pub brokers: Vec<String>,
    #[serde(default = "default_kafka_cdr_topic")]
    pub cdr_topic: String,
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: Vec::new(),
            cdr_topic: default_kafka_cdr_topic(),
        }
    }
}

fn default_redis_nodes() -> Vec<String> {
    vec!["redis://127.0.0.1:6379".into()]
}

fn default_postgres_url() -> String {
    "postgres://127.0.0.1:5432/sipora".into()
}

/// SIP upstream pool for `sipora-lb` (distinct from `redis.nodes`, which is the Redis URL).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpstreamsConfig {
    /// UDP `host:port` targets for backend SIP proxies (IP literals or resolvable hostnames).
    #[serde(default)]
    pub lb_sip_proxies: Vec<String>,
}

fn default_sip_domain() -> String {
    "example.com".into()
}
fn default_sip_udp_port() -> u16 {
    5060
}
fn default_sips_port() -> u16 {
    5061
}
fn default_wss_port() -> u16 {
    443
}
fn default_outbound_port() -> u16 {
    5065
}
fn default_health_port() -> u16 {
    8080
}
fn default_tls_min_version() -> String {
    "1.3".into()
}
fn default_true() -> bool {
    true
}
fn default_cert_renew_threshold() -> f64 {
    0.8
}
fn default_acme_provider() -> String {
    "letsencrypt".into()
}
fn default_register_rate() -> u32 {
    20
}
fn default_invite_rate() -> u32 {
    10
}
fn default_dialog_rate() -> u32 {
    100
}
fn default_block_threshold() -> u32 {
    5
}
fn default_block_window_s() -> u64 {
    60
}
fn default_block_cooldown_s() -> u64 {
    300
}
fn default_min_expires() -> u32 {
    60
}
fn default_max_expires() -> u32 {
    3600
}
fn default_default_expires() -> u32 {
    600
}
fn default_nonce_ttl_s() -> u64 {
    60
}
fn default_max_forwards() -> u8 {
    70
}
fn default_trace_header() -> String {
    "X-Trace-ID".into()
}
fn default_location_timeout_ms() -> u64 {
    50
}
fn default_nonce_len() -> usize {
    32
}
fn default_auth_timeout_ms() -> u64 {
    50
}
fn default_max_call_s() -> u64 {
    14400
}
fn default_pool_size() -> u32 {
    200
}
fn default_cdr_retention_months() -> u32 {
    24
}
fn default_otlp_endpoint() -> String {
    "http://localhost:4317".into()
}
fn default_service_name() -> String {
    "sipora".into()
}
fn default_metrics_interval_s() -> u64 {
    15
}
fn default_success_sample_rate() -> f64 {
    0.05
}
fn default_rtpengine_host() -> String {
    "rtp-proxy".into()
}
fn default_rtpengine_ice() -> String {
    "remove".into()
}
fn default_rtpengine_dtls() -> String {
    "passive".into()
}
fn default_allowed_codecs() -> Vec<String> {
    vec!["opus".into(), "G722".into(), "G711u".into(), "G711a".into()]
}
fn default_rtp_timeout_s() -> u64 {
    30
}
fn default_kafka_cdr_topic() -> String {
    "sip.cdrs".into()
}
fn default_stir_mode() -> String {
    "disabled".into()
}
fn default_attest_level() -> String {
    "A".into()
}

impl SiporaConfig {
    /// Loads using the default file stem `sipora` (e.g. `sipora.toml` in the working directory).
    pub fn load() -> Result<Self, config::ConfigError> {
        Self::load_from_config_input("sipora")
    }

    /// Loads configuration from the same sources as [`load`](Self::load), but chooses the file by
    /// `config_input` (typically from `--config` / `SIPORA_CONFIG`):
    ///
    /// - **Stem** (e.g. `prod`, `sipora`): same as `config::File::with_name` (tries `prod.toml`, etc.).
    /// - **Path** (existing file, or contains `/`, `\\`, or ends in `.toml`/`.yaml`/`.yml`): load that path.
    ///
    /// Environment `SIPORA__*` still merges on top. Empty input is treated as `sipora`.
    ///
    /// After deserialize, [`StirConfig::validate`](StirConfig::validate) runs so invalid
    /// `[stir]` values fail fast (raw `try_deserialize` skips this). The returned `stir` is
    /// replaced with the normalized `StirConfig` from `validate` (trimmed, lowercased `mode` and
    /// `attest`).
    pub fn load_from_config_input(config_input: &str) -> Result<Self, config::ConfigError> {
        let input = config_input.trim();
        let input = if input.is_empty() { "sipora" } else { input };

        let path = Path::new(input);
        let builder = config::Config::builder();
        let builder = if path.is_file() || looks_like_explicit_path(input) {
            builder.add_source(config::File::from(path).required(false))
        } else {
            builder.add_source(config::File::with_name(input).required(false))
        };
        let builder =
            builder.add_source(config::Environment::with_prefix("SIPORA").separator("__"));
        let mut cfg: SiporaConfig = builder.build()?.try_deserialize()?;
        cfg.stir = cfg.stir.validate()?;
        Ok(cfg)
    }
}

fn looks_like_explicit_path(s: &str) -> bool {
    s.contains('/')
        || s.contains('\\')
        || s.ends_with(".toml")
        || s.ends_with(".yaml")
        || s.ends_with(".yml")
}
