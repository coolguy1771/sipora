use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use moka::future::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

/// PASSporT is invalid if its iat is older than this (RFC 8224 §3).
const PASSPORT_MAX_AGE_S: u64 = 60;

/// STIR attestation level (RFC 8588 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestLevel {
    /// A — full attestation: SP authenticates the subscriber and their number.
    Full,
    /// B — partial attestation: SP authenticates the subscriber but not the specific number.
    Partial,
    /// C — gateway attestation: SP received a call via a gateway with no verification.
    Gateway,
}

/// Parsed and verified PASSporT data.
#[derive(Debug, Clone)]
pub struct StirResult {
    pub attest: AttestLevel,
    pub orig_tn: String,
    pub dest_tn: Vec<String>,
    pub iat: u64,
    pub origid: String,
    pub cert_url: String,
}

#[derive(Debug, Error)]
pub enum StirError {
    #[error("missing Identity header")]
    MissingHeader,
    #[error("malformed Identity header: {0}")]
    MalformedHeader(String),
    #[error("certificate fetch failed: {0}")]
    CertFetch(String),
    #[error("certificate parse failed: {0}")]
    CertParse(String),
    #[error("JWT verification failed: {0}")]
    JwtInvalid(String),
    #[error("stale PASSporT (iat too old)")]
    Stale,
    #[error("unknown attest value: {0}")]
    UnknownAttest(String),
    #[error("signing failed: {0}")]
    SignError(String),
    #[error("certificate chain verification failed: {0}")]
    ChainInvalid(String),
}

// PASSporT JWT claims (RFC 8225 §5).
#[derive(Debug, Serialize, Deserialize)]
struct OrigTn {
    tn: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DestTns {
    tn: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PassportClaims {
    iat: u64,
    orig: OrigTn,
    dest: DestTns,
    attest: String,
    origid: String,
}

/// In-memory cert PEM cache keyed by URL.
///
/// Certs have long validity periods (typically years). We cache for 1 h to
/// avoid repeatedly fetching the same STI-CA cert on every call.
///
/// Both `moka::future::Cache` and `reqwest::Client` are cheaply `Clone`
/// (reference-counted internally), so `CertCache` can be freely shared.
#[derive(Clone)]
pub struct CertCache {
    inner: Cache<String, String>,
    http: Client,
}

impl CertCache {
    pub fn new() -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(512)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            http: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest TLS client"),
        }
    }

    async fn fetch_cert_pem(&self, url: &str) -> Result<String, StirError> {
        let parsed = Url::parse(url).map_err(|e| StirError::CertFetch(e.to_string()))?;
        if parsed.scheme() != "https" {
            return Err(StirError::CertFetch(format!(
                "certificate URL must use https (got scheme {:?})",
                parsed.scheme()
            )));
        }
        if let Some(cached) = self.inner.get(url).await {
            return Ok(cached);
        }
        let pem = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| StirError::CertFetch(e.to_string()))?
            .text()
            .await
            .map_err(|e| StirError::CertFetch(e.to_string()))?;
        let ders = read_pem_certificate_ders(&pem)?;
        let leaf = ders
            .first()
            .ok_or_else(|| StirError::CertParse("empty certificate PEM".into()))?;
        let _spki = spki_pem_from_cert_der(leaf)?;
        self.inner.insert(url.to_owned(), pem.clone()).await;
        Ok(pem)
    }

    /// Seed the in-memory cert cache (tests only); avoids outbound HTTP for `fetch_cert_pem`.
    #[cfg(test)]
    pub async fn insert_pem_for_test(&self, url: impl Into<String>, pem: String) {
        self.inner.insert(url.into(), pem).await;
    }
}

impl Default for CertCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse `<jwt>;info=<url>;alg=ES256` → (jwt_token, cert_url).
///
/// Handles the three Identity-header value forms from RFC 8224 §9.2:
/// - `compact-jwt;info=<url>;alg=ES256`
/// - `<compact-jwt>;info=<url>;alg=ES256`
/// - `"compact-jwt";info=<url>;alg=ES256`
fn parse_identity_header(value: &str) -> Result<(String, String), StirError> {
    let mut iter = value.trim().splitn(2, ';');
    let token_raw = iter
        .next()
        .ok_or_else(|| StirError::MalformedHeader("empty value".into()))?;
    let rest = iter.next().unwrap_or("");

    let token = token_raw
        .trim()
        .trim_matches(|c| c == '<' || c == '>' || c == '"')
        .to_owned();

    let mut info_url: Option<String> = None;
    for param in rest.split(';') {
        let param = param.trim();
        if let Some(raw_url) = param.strip_prefix("info=") {
            info_url = Some(
                raw_url
                    .trim()
                    .trim_matches(|c| c == '<' || c == '>' || c == '"')
                    .to_owned(),
            );
        }
    }

    let url = info_url
        .filter(|u| !u.is_empty())
        .ok_or_else(|| StirError::MalformedHeader("missing info= parameter".into()))?;

    Ok((token, url))
}

/// Extract the SubjectPublicKeyInfo from a PEM-encoded X.509 certificate and
/// re-encode it as a `-----BEGIN PUBLIC KEY-----` PEM string suitable for
/// `jsonwebtoken::DecodingKey::from_ec_pem`.
fn spki_pem_from_cert_der(cert_der: &[u8]) -> Result<String, StirError> {
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode};

    let cert = Certificate::from_der(cert_der).map_err(|e| StirError::CertParse(e.to_string()))?;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| StirError::CertParse(e.to_string()))?;

    let b64 = B64.encode(&spki_der);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"
    ))
}

fn spki_pem_from_cert_pem(cert_pem: &str) -> Result<String, StirError> {
    let ders = read_pem_certificate_ders(cert_pem)?;
    let leaf = ders
        .first()
        .ok_or_else(|| StirError::CertParse("empty PEM".into()))?;
    spki_pem_from_cert_der(leaf)
}

fn read_pem_certificate_ders(pem: &str) -> Result<Vec<Vec<u8>>, StirError> {
    let mut rd = Cursor::new(pem.as_bytes());
    rustls_pemfile::certs(&mut rd)
        .map(|r| {
            r.map(|c| c.as_ref().to_vec())
                .map_err(|e| StirError::CertParse(format!("PEM certificates: {e}")))
        })
        .collect()
}

const MAX_STIR_CHAIN_DEPTH: usize = 16;

fn cert_valid_now_x509(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), StirError> {
    use x509_parser::time::ASN1Time;

    let now = ASN1Time::now();
    let v = cert.validity();
    if v.not_before > now || v.not_after < now {
        return Err(StirError::ChainInvalid(
            "certificate outside validity period".into(),
        ));
    }
    Ok(())
}

fn verify_signed_by_anchor(
    cur: &x509_parser::certificate::X509Certificate<'_>,
    anchor: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<(), StirError> {
    assert_valid_ca_issuer(anchor, "trust anchor")?;
    cur.verify_signature(Some(anchor.public_key()))
        .map_err(|e| StirError::ChainInvalid(format!("signed-by-anchor verification: {e}")))?;
    anchor
        .verify_signature(None)
        .map_err(|e| StirError::ChainInvalid(format!("trust anchor self-signature: {e}")))?;
    Ok(())
}

/// Enforce PKIX CA semantics for a certificate that may sign another cert in the chain.
fn assert_valid_ca_issuer(
    issuer: &x509_parser::certificate::X509Certificate<'_>,
    ctx: &str,
) -> Result<(), StirError> {
    use x509_parser::extensions::ParsedExtension;

    let mut has_basic_constraints = false;
    let mut is_ca = false;
    let mut saw_key_usage = false;
    let mut key_cert_sign = false;

    for ext in issuer.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                has_basic_constraints = true;
                is_ca = bc.ca;
            }
            ParsedExtension::KeyUsage(ku) => {
                saw_key_usage = true;
                key_cert_sign = ku.key_cert_sign();
            }
            _ => {}
        }
    }

    if !has_basic_constraints || !is_ca {
        return Err(StirError::ChainInvalid(format!(
            "{ctx}: signing certificate must be a CA (basicConstraints cA true)"
        )));
    }

    if saw_key_usage && !key_cert_sign {
        return Err(StirError::ChainInvalid(format!(
            "{ctx}: signing certificate lacks keyCertSign in keyUsage"
        )));
    }

    Ok(())
}

fn verify_chain_to_trust_anchors(chain: &[Vec<u8>], anchors: &[Vec<u8>]) -> Result<(), StirError> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    if chain.is_empty() {
        return Err(StirError::CertParse(
            "no certificates in Identity cert PEM".into(),
        ));
    }
    if anchors.is_empty() {
        return Err(StirError::CertParse(
            "no STIR trust anchor certificates".into(),
        ));
    }

    let mut idx = 0usize;
    for _ in 0..MAX_STIR_CHAIN_DEPTH {
        let (_, cur) = X509Certificate::from_der(chain[idx].as_slice())
            .map_err(|e| StirError::CertParse(e.to_string()))?;
        cert_valid_now_x509(&cur)?;

        for ader in anchors {
            let (_, anchor) = X509Certificate::from_der(ader.as_slice())
                .map_err(|e| StirError::CertParse(e.to_string()))?;
            if anchor.subject() == cur.issuer() {
                return verify_signed_by_anchor(&cur, &anchor);
            }
        }

        let mut advanced = false;
        if idx + 1 < chain.len() {
            let (_, nxt) = X509Certificate::from_der(chain[idx + 1].as_slice())
                .map_err(|e| StirError::CertParse(e.to_string()))?;
            if nxt.subject() == cur.issuer() {
                assert_valid_ca_issuer(&nxt, "chain issuer")?;
                cur.verify_signature(Some(nxt.public_key()))
                    .map_err(|e| StirError::ChainInvalid(format!("chain signature: {e}")))?;
                idx += 1;
                advanced = true;
            }
        }
        if !advanced {
            for (j, der) in chain.iter().enumerate().skip(idx + 1) {
                let (_, issuer) = X509Certificate::from_der(der.as_slice())
                    .map_err(|e| StirError::CertParse(e.to_string()))?;
                if issuer.subject() == cur.issuer() {
                    assert_valid_ca_issuer(&issuer, "chain issuer")?;
                    cur.verify_signature(Some(issuer.public_key()))
                        .map_err(|e| StirError::ChainInvalid(format!("chain signature: {e}")))?;
                    idx = j;
                    advanced = true;
                    break;
                }
            }
        }
        if advanced {
            continue;
        }

        return Err(StirError::ChainInvalid(
            "no issuer matching an intermediate or trust anchor".into(),
        ));
    }

    Err(StirError::ChainInvalid("chain exceeded max depth".into()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Verify a STIR Identity header value.
///
/// Fetches the cert from the `info=` URL, verifies the ES256 PASSporT JWT,
/// and enforces the 60-second freshness window from RFC 8224 §3.
///
/// When `trust_anchor_pem` is set, enforces PKIX path validation of the fetched
/// certificate chain to those anchors (RFC 8226 §5) before trusting the leaf SPKI.
pub async fn verify_identity_header(
    identity_value: &str,
    cache: &CertCache,
    trust_anchor_pem: Option<&str>,
) -> Result<StirResult, StirError> {
    let (token, cert_url) = parse_identity_header(identity_value)?;

    let cert_pem = cache.fetch_cert_pem(&cert_url).await?;
    if let Some(anchors) = trust_anchor_pem {
        let chain = read_pem_certificate_ders(&cert_pem)?;
        let roots = read_pem_certificate_ders(anchors)?;
        verify_chain_to_trust_anchors(&chain, &roots)?;
    }
    let pubkey_pem = spki_pem_from_cert_pem(&cert_pem)?;
    let decoding_key = DecodingKey::from_ec_pem(pubkey_pem.as_bytes())
        .map_err(|e| StirError::CertParse(e.to_string()))?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims = HashSet::new(); // PASSporT has no exp/sub
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let token_data = decode::<PassportClaims>(&token, &decoding_key, &validation)
        .map_err(|e| StirError::JwtInvalid(e.to_string()))?;

    let claims = token_data.claims;

    if now_secs().saturating_sub(claims.iat) > PASSPORT_MAX_AGE_S {
        return Err(StirError::Stale);
    }

    let attest = match claims.attest.as_str() {
        "A" => AttestLevel::Full,
        "B" => AttestLevel::Partial,
        "C" => AttestLevel::Gateway,
        other => return Err(StirError::UnknownAttest(other.to_owned())),
    };

    Ok(StirResult {
        attest,
        orig_tn: claims.orig.tn,
        dest_tn: claims.dest.tn,
        iat: claims.iat,
        origid: claims.origid,
        cert_url,
    })
}

/// Sign a new PASSporT and return the compact JWT.
///
/// `privkey_pem`: EC private key PEM (`BEGIN EC PRIVATE KEY` or `BEGIN PRIVATE KEY`).
/// `cert_url`: publicly reachable URL for the STI-AS signing certificate.
pub fn sign_passport(
    orig_tn: &str,
    dest_tn: &[&str],
    attest: AttestLevel,
    origid: &str,
    privkey_pem: &[u8],
    cert_url: &str,
) -> Result<String, StirError> {
    let iat = now_secs();
    let claims = PassportClaims {
        iat,
        orig: OrigTn {
            tn: orig_tn.to_owned(),
        },
        dest: DestTns {
            tn: dest_tn.iter().map(|s| (*s).to_owned()).collect(),
        },
        attest: match attest {
            AttestLevel::Full => "A".to_owned(),
            AttestLevel::Partial => "B".to_owned(),
            AttestLevel::Gateway => "C".to_owned(),
        },
        origid: origid.to_owned(),
    };

    let header = Header {
        alg: Algorithm::ES256,
        typ: Some("passport".to_owned()),
        x5u: Some(cert_url.to_owned()),
        ..Default::default()
    };

    let key =
        EncodingKey::from_ec_pem(privkey_pem).map_err(|e| StirError::SignError(e.to_string()))?;

    encode(&header, &claims, &key).map_err(|e| StirError::SignError(e.to_string()))
}

/// Build the full Identity header value from a signed PASSporT and cert URL.
///
/// Format per RFC 8224 §9.2:
/// `<token>;info=<cert_url>;alg=ES256`
pub fn identity_header_value(token: &str, cert_url: &str) -> String {
    format!("{token};info=<{cert_url}>;alg=ES256")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
    use std::collections::HashSet;

    /// Build a deterministic P-256 test key pair and return (private_pem, public_pem).
    ///
    /// Uses a fixed 32-byte secret so tests are deterministic and require no RNG.
    /// The scalar 0x01_01_..._01 is well within the P-256 curve order.
    fn test_ec_p256_pem_pair() -> (Vec<u8>, Vec<u8>) {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        let secret_bytes = [0x01u8; 32];
        let key = SigningKey::from_bytes(secret_bytes.as_ref().into()).expect("valid scalar");
        let priv_pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private key PEM")
            .to_string();
        let pub_pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public key PEM");
        (priv_pem.into_bytes(), pub_pem.into_bytes())
    }

    #[test]
    fn parse_identity_header_with_angle_brackets() {
        let (tok, url) = parse_identity_header(
            "eyJhbGciOiJFUzI1NiJ9.payload.sig;info=<https://example.com/cert.pem>;alg=ES256",
        )
        .unwrap();
        assert_eq!(tok, "eyJhbGciOiJFUzI1NiJ9.payload.sig");
        assert_eq!(url, "https://example.com/cert.pem");
    }

    #[test]
    fn parse_identity_header_without_brackets() {
        let (tok, url) = parse_identity_header(
            "eyJhbGciOiJFUzI1NiJ9.payload.sig;info=https://example.com/cert.pem;alg=ES256",
        )
        .unwrap();
        assert_eq!(tok, "eyJhbGciOiJFUzI1NiJ9.payload.sig");
        assert_eq!(url, "https://example.com/cert.pem");
    }

    #[test]
    fn parse_identity_header_missing_info_errors() {
        assert!(parse_identity_header("token_only").is_err());
        assert!(parse_identity_header("token;alg=ES256").is_err());
    }

    #[test]
    fn identity_header_value_format() {
        let v = identity_header_value("tok.en.sig", "https://example.com/cert.pem");
        assert_eq!(
            v,
            "tok.en.sig;info=<https://example.com/cert.pem>;alg=ES256"
        );
    }

    #[test]
    fn sign_passport_and_verify_claims() {
        let (priv_pem, pub_pem) = test_ec_p256_pem_pair();

        let token = sign_passport(
            "15551234567",
            &["15557654321"],
            AttestLevel::Full,
            "test-origid-abc",
            &priv_pem,
            "https://example.com/cert.pem",
        )
        .unwrap();

        // Verify directly with the matching public key (bypassing cert fetch).
        let decoding_key = DecodingKey::from_ec_pem(&pub_pem).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;

        let data = decode::<PassportClaims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(data.claims.attest, "A");
        assert_eq!(data.claims.orig.tn, "15551234567");
        assert_eq!(data.claims.dest.tn, vec!["15557654321"]);
        assert_eq!(data.claims.origid, "test-origid-abc");
    }

    #[test]
    fn sign_passport_all_attest_levels() {
        let (priv_pem, pub_pem) = test_ec_p256_pem_pair();

        for (level, expected) in [
            (AttestLevel::Full, "A"),
            (AttestLevel::Partial, "B"),
            (AttestLevel::Gateway, "C"),
        ] {
            let token = sign_passport(
                "15550000001",
                &["15550000002"],
                level,
                "oid",
                &priv_pem,
                "https://example.com/cert.pem",
            )
            .unwrap();

            let key = DecodingKey::from_ec_pem(&pub_pem).unwrap();
            let mut v = Validation::new(Algorithm::ES256);
            v.required_spec_claims = HashSet::new();
            v.validate_exp = false;
            let data = decode::<PassportClaims>(&token, &key, &v).unwrap();
            assert_eq!(data.claims.attest, expected);
        }
    }

    #[tokio::test]
    async fn stale_passport_iat_check() {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rcgen key");
        let cert = CertificateParams::new(vec!["localhost".into()])
            .expect("certificate params")
            .self_signed(&key_pair)
            .expect("self_signed cert");
        let cert_pem = cert.pem();
        let priv_pem = key_pair.serialize_pem();

        let claims = PassportClaims {
            iat: 1_000_000_000, // year 2001 — definitely stale
            orig: OrigTn {
                tn: "15551234567".into(),
            },
            dest: DestTns {
                tn: vec!["15557654321".into()],
            },
            attest: "A".into(),
            origid: "stale-id".into(),
        };
        let header = Header {
            alg: Algorithm::ES256,
            typ: Some("passport".into()),
            ..Default::default()
        };
        let key = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
        let token = encode(&header, &claims, &key).unwrap();

        let age = now_secs().saturating_sub(claims.iat);
        assert!(age > PASSPORT_MAX_AGE_S);

        let cert_url = "https://example.invalid/sipora-stir-test-cert.pem";
        let identity = identity_header_value(&token, cert_url);
        let cache = CertCache::new();
        cache.insert_pem_for_test(cert_url, cert_pem).await;

        let err = verify_identity_header(&identity, &cache, None)
            .await
            .expect_err("stale iat must be rejected");
        assert!(matches!(err, StirError::Stale));
    }

    #[tokio::test]
    async fn stir_chain_accepts_leaf_signed_by_trusted_ca() {
        use rcgen::{CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};

        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let ee_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let ee_params = CertificateParams::new(vec!["sip.stir.test".into()]).unwrap();
        let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();

        let chain_pem = format!("{}{}", ee_cert.pem(), ca_cert.pem());
        let anchor_pem = ca_cert.pem();
        let priv_pem = ee_key.serialize_pem();

        let token = sign_passport(
            "15551234567",
            &["15557654321"],
            AttestLevel::Full,
            "oid",
            priv_pem.as_bytes(),
            "https://stir-chain.example/cert.pem",
        )
        .unwrap();
        let identity = identity_header_value(&token, "https://stir-chain.example/cert.pem");
        let cache = CertCache::new();
        cache
            .insert_pem_for_test("https://stir-chain.example/cert.pem", chain_pem)
            .await;

        let r = verify_identity_header(&identity, &cache, Some(anchor_pem.as_str()))
            .await
            .unwrap();
        assert_eq!(r.attest, AttestLevel::Full);
    }

    #[tokio::test]
    async fn stir_chain_rejects_wrong_trust_anchor() {
        use rcgen::{CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};

        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let ee_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let ee_params = CertificateParams::new(vec!["sip.stir.test".into()]).unwrap();
        let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();

        let chain_pem = format!("{}{}", ee_cert.pem(), ca_cert.pem());

        let other_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let other_ca = CertificateParams::new(vec![])
            .unwrap()
            .self_signed(&other_key)
            .unwrap();
        let wrong_anchor_pem = other_ca.pem();
        let priv_pem = ee_key.serialize_pem();

        let token = sign_passport(
            "15551234567",
            &["15557654321"],
            AttestLevel::Full,
            "oid",
            priv_pem.as_bytes(),
            "https://stir-chain.example/cert.pem",
        )
        .unwrap();
        let identity = identity_header_value(&token, "https://stir-chain.example/cert.pem");
        let cache = CertCache::new();
        cache
            .insert_pem_for_test("https://stir-chain.example/cert.pem", chain_pem)
            .await;

        let err = verify_identity_header(&identity, &cache, Some(wrong_anchor_pem.as_str()))
            .await
            .expect_err("untrusted anchor must fail chain validation");
        assert!(matches!(err, StirError::ChainInvalid(_)));
    }
}
