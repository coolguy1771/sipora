use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use sipora_api::store::{AppState, DataStoreKind, new_mock_store};
use std::sync::Arc;
use tower::ServiceExt;

// Only used by `api_http_e2e`; `api_postgres_e2e` shares this module for HTTP helpers.
#[allow(dead_code)]
pub fn mock_state(domain: &str, token: Option<&str>) -> Arc<AppState> {
    Arc::new(AppState {
        domain: domain.to_string(),
        api_bearer_token: token.map(String::from),
        store: new_mock_store(),
        store_kind: DataStoreKind::Mock,
    })
}

pub async fn text_response(
    app: Router,
    req: Request<Body>,
) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 256 * 1024)
        .await
        .expect("read body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

pub fn bearer(token: &str) -> (header::HeaderName, header::HeaderValue) {
    (
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
    )
}
