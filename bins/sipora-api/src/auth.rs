use crate::store::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;

pub async fn require_provisioning_auth(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path();
    if !path.starts_with("/api/") {
        return Ok(next.run(req).await);
    }

    let Some(ref expected) = state.api_bearer_token else {
        let body = json!({
            "error": "provisioning API disabled",
            "detail": "Set auth.api_bearer_token or SIPORA__AUTH__API_BEARER_TOKEN.",
        });
        return Ok((StatusCode::FORBIDDEN, axum::Json(body)).into_response());
    };

    let Some(hdr) = req.headers().get(AUTHORIZATION) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let Ok(hdr_str) = hdr.to_str() else {
        return Err(StatusCode::BAD_REQUEST);
    };

    let prefix = "Bearer ";
    let Some(got) = hdr_str.strip_prefix(prefix) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if !constant_time_eq(got.trim().as_bytes(), expected.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
