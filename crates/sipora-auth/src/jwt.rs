use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub exp: u64,
    pub iss: Option<String>,
    pub aud: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    n: String,
    e: String,
}

pub struct JwksCache {
    keys: Arc<RwLock<Option<DecodingKey>>>,
    jwks_url: String,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
}

impl JwksCache {
    pub fn new(
        jwks_url: &str,
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
    ) -> Self {
        Self {
            keys: Arc::new(RwLock::new(None)),
            jwks_url: jwks_url.to_owned(),
            expected_issuer,
            expected_audience,
        }
    }

    pub fn url(&self) -> &str {
        &self.jwks_url
    }

    /// Fetch JWKS and cache the first RSA public key (for operators / tests).
    pub async fn refresh_jwks(&self) -> crate::Result<()> {
        self.fetch_and_store(None).await
    }

    pub async fn validate_token(&self, token: &str) -> crate::Result<JwtClaims> {
        if self.keys.read().await.is_none() {
            let hdr =
                decode_header(token).map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?;
            self.fetch_and_store(hdr.kid.as_deref()).await?;
        }

        let key = self.keys.read().await;
        let decoding_key = key
            .as_ref()
            .ok_or_else(|| crate::AuthError::JwtInvalid("JWKS not loaded".into()))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        if let Some(ref iss) = self.expected_issuer {
            validation.set_issuer(&[iss.as_str()]);
        }
        if let Some(ref aud) = self.expected_audience {
            validation.set_audience(&[aud.as_str()]);
        } else {
            validation.validate_aud = false;
        }

        let token_data = decode::<JwtClaims>(token, decoding_key, &validation)
            .map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?;

        Ok(token_data.claims)
    }

    async fn fetch_and_store(&self, kid: Option<&str>) -> crate::Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?;
        let body = client
            .get(self.jwks_url.as_str())
            .send()
            .await
            .map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?
            .error_for_status()
            .map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?
            .text()
            .await
            .map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?;
        let set: JwkSet =
            serde_json::from_str(&body).map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?;
        let jwk = pick_rsa(&set, kid)
            .ok_or_else(|| crate::AuthError::JwtInvalid("no suitable RSA key in JWKS".into()))?;
        let dk = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| crate::AuthError::JwtInvalid(e.to_string()))?;
        *self.keys.write().await = Some(dk);
        Ok(())
    }

    pub fn sub_to_aor(sub: &str, domain: &str) -> String {
        format!("sip:{sub}@{domain}")
    }
}

fn pick_rsa<'a>(set: &'a JwkSet, kid: Option<&str>) -> Option<&'a Jwk> {
    kid.and_then(|k| {
        set.keys
            .iter()
            .find(|j| j.kty == "RSA" && j.kid.as_deref() == Some(k))
    })
    .or_else(|| set.keys.iter().find(|j| j.kty == "RSA"))
}
