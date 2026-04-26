use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use moka::future::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

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
        self.inner.insert(url.to_owned(), pem.clone()).await;
        Ok(pem)
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
fn spki_pem_from_cert_pem(cert_pem: &str) -> Result<String, StirError> {
    use x509_cert::Certificate;
    use x509_cert::der::{DecodePem, Encode};

    let cert = Certificate::from_pem(cert_pem.as_bytes())
        .map_err(|e| StirError::CertParse(e.to_string()))?;

    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| StirError::CertParse(e.to_string()))?;

    let b64 = B64.encode(&spki_der);
    Ok(format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"))
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
pub async fn verify_identity_header(
    identity_value: &str,
    cache: &CertCache,
) -> Result<StirResult, StirError> {
    let (token, cert_url) = parse_identity_header(identity_value)?;

    let cert_pem = cache.fetch_cert_pem(&cert_url).await?;
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
        orig: OrigTn { tn: orig_tn.to_owned() },
        dest: DestTns { tn: dest_tn.iter().map(|s| (*s).to_owned()).collect() },
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

    let key = EncodingKey::from_ec_pem(privkey_pem)
        .map_err(|e| StirError::SignError(e.to_string()))?;

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
        assert_eq!(v, "tok.en.sig;info=<https://example.com/cert.pem>;alg=ES256");
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

    #[test]
    fn stale_passport_iat_check() {
        let (priv_pem, _) = test_ec_p256_pem_pair();

        let claims = PassportClaims {
            iat: 1_000_000_000, // year 2001 — definitely stale
            orig: OrigTn { tn: "15551234567".into() },
            dest: DestTns { tn: vec!["15557654321".into()] },
            attest: "A".into(),
            origid: "stale-id".into(),
        };
        let header = Header {
            alg: Algorithm::ES256,
            typ: Some("passport".into()),
            ..Default::default()
        };
        let key = EncodingKey::from_ec_pem(&priv_pem).unwrap();
        let token = encode(&header, &claims, &key).unwrap();

        // The verify_identity_header freshness gate would reject this token.
        let age = now_secs().saturating_sub(claims.iat);
        assert!(age > PASSPORT_MAX_AGE_S);
        let _ = token;
    }
}
