//! End-to-end HTTP tests against the real Axum router (mock store, no subprocess).

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use sipora_api::router;
use support::{bearer, mock_state, text_response};
use tower::ServiceExt;

const DOMAIN: &str = "sip.example.com";
const TOKEN: &str = "e2e-test-bearer-token";

fn app_mock() -> axum::Router {
    router(mock_state(DOMAIN, Some(TOKEN)))
}

#[tokio::test]
async fn health_returns_json_and_security_headers() {
    let app = app_mock();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    let (st, body): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "healthy");
    assert_eq!(v["data_store"], "mock");
}

#[tokio::test]
async fn ready_ok_for_mock_store() {
    let app = app_mock();
    let (st, _): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/ready")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn openapi_json_served() {
    let app = app_mock();
    let (st, body): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/api-docs/openapi.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(doc.get("openapi").is_some() || doc.get("swagger").is_some());
}

#[tokio::test]
async fn swagger_ui_route_exists() {
    let app = app_mock();
    let (st, _): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/swagger-ui")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        st == StatusCode::OK
            || st == StatusCode::MOVED_PERMANENTLY
            || st == StatusCode::FOUND
            || st == StatusCode::SEE_OTHER,
        "unexpected status {st}"
    );
}

#[tokio::test]
async fn api_disabled_without_bearer_config() {
    let app = router(mock_state(DOMAIN, None));
    let (st, body): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/api/v1/users")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(body.contains("provisioning API disabled"));
}

#[tokio::test]
async fn api_unauthorized_without_header() {
    let app = app_mock();
    let (st, _): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/api/v1/users")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_unauthorized_wrong_token() {
    let app = app_mock();
    let (h, v) = bearer("wrong-token");
    let (st, _): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/api/v1/users")
            .header(h, v)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn users_list_empty_then_create_list_get() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let (st, body): (StatusCode, String) = text_response(
        app.clone(),
        Request::builder()
            .uri("/api/v1/users")
            .header(bh.clone(), bv.clone())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let list: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(list.is_empty());

    let create = json!({
        "username": "alice",
        "domain": DOMAIN,
        "password": "s3cret-long",
        "enabled": true,
    });
    let (st, body): (StatusCode, String) = text_response(
        app.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/users")
            .header(bh.clone(), bv.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(create.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "body={body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let (st, body): (StatusCode, String) = text_response(
        app.clone(),
        Request::builder()
            .uri("/api/v1/users")
            .header(bh.clone(), bv.clone())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let list: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["username"], "alice");

    let (st, body): (StatusCode, String) = text_response(
        app.clone(),
        Request::builder()
            .uri(format!("/api/v1/users/{id}"))
            .header(bh.clone(), bv.clone())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let u: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(u["username"], "alice");
    assert_eq!(u["domain"], DOMAIN);
}

#[tokio::test]
async fn create_user_rejects_domain_mismatch() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let create = json!({
        "username": "bob",
        "domain": "other.example",
        "password": "x",
    });
    let (st, body): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/users")
            .header(bh, bv)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(create.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(body.contains("general.domain"));
}

#[tokio::test]
async fn create_user_conflict_duplicate() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let create = json!({
        "username": "dup",
        "domain": DOMAIN,
        "password": "p1",
    });
    for _ in 0..2 {
        let _: (StatusCode, String) = text_response(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header(bh.clone(), bv.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(create.to_string()))
                .unwrap(),
        )
        .await;
    }
    let (st, body): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/users")
            .header(bh, bv)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(create.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "body={body}");
}

#[tokio::test]
async fn create_user_validation_empty_fields() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let create = json!({
        "username": "",
        "domain": DOMAIN,
        "password": "x",
    });
    let (st, _): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/users")
            .header(bh, bv)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(create.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_user_invalid_uuid() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let (st, _): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/api/v1/users/not-a-uuid")
            .header(bh, bv)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_user_not_found() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let id = uuid::Uuid::new_v4();
    let (st, _): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri(format!("/api/v1/users/{id}"))
            .header(bh, bv)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cdrs_empty_on_mock() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let (st, body): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/api/v1/cdrs")
            .header(bh, bv)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["records"], json!([]));
}

#[tokio::test]
async fn cdrs_bad_correlation_id() {
    let app = app_mock();
    let (bh, bv) = bearer(TOKEN);
    let (st, body): (StatusCode, String) = text_response(
        app,
        Request::builder()
            .uri("/api/v1/cdrs?correlation_id=bad")
            .header(bh, bv)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(body.contains("correlation_id"));
}
