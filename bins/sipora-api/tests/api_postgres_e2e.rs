//! API tests against PostgreSQL. Runs when `DATABASE_URL` is set (integration CI).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use sipora_api::{router, store};
use sipora_core::config::PostgresConfig;
use std::sync::Arc;
use tower::ServiceExt;

mod support;
use support::{bearer, text_response};

const DOMAIN: &str = "sip.example.com";
const TOKEN: &str = "postgres-e2e-token";

fn skip_reason() -> Option<String> {
    match std::env::var("DATABASE_URL") {
        Ok(s) if !s.is_empty() => None,
        _ => Some("DATABASE_URL not set (Postgres API e2e skipped)".into()),
    }
}

#[tokio::test]
async fn postgres_create_list_get_user() {
    if let Some(msg) = skip_reason() {
        eprintln!("{msg}");
        return;
    }
    let url = std::env::var("DATABASE_URL").unwrap();
    let cfg = PostgresConfig {
        url,
        max_pool_size: 5,
        cdr_retention_months: 24,
    };
    let pool = sipora_data::pg::connect_pool(&cfg)
        .await
        .expect("postgres connect");
    sipora_data::pg::verify_provisioning_schema(&pool)
        .await
        .expect("schema");

    let state = Arc::new(store::AppState {
        domain: DOMAIN.into(),
        api_bearer_token: Some(TOKEN.into()),
        store: store::ApiStore::Postgres(pool),
        store_kind: store::DataStoreKind::Postgres,
    });
    let app = router(state);

    let suffix = uuid::Uuid::new_v4();
    let username = format!("e2e_{suffix}");
    let (bh, bv) = bearer(TOKEN);
    let create = json!({
        "username": username,
        "domain": DOMAIN,
        "password": "e2e-password-unique",
        "enabled": true,
    });
    let (st, body) = text_response(
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
    let id = created["id"].as_str().unwrap();

    let (st, body) = text_response(
        app.clone(),
        Request::builder()
            .uri(format!("/api/v1/users/{id}"))
            .header(bh.clone(), bv.clone())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "body={body}");
    let u: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(u["username"], username);

    let (st, body) = text_response(
        app,
        Request::builder()
            .uri("/api/v1/users")
            .header(bh, bv)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let list: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(
        list.iter().any(|row| row["username"] == username),
        "expected user in list: {list:?}"
    );
}

#[tokio::test]
async fn postgres_ready_checks_database() {
    if let Some(msg) = skip_reason() {
        eprintln!("{msg}");
        return;
    }
    let url = std::env::var("DATABASE_URL").unwrap();
    let cfg = PostgresConfig {
        url,
        max_pool_size: 3,
        cdr_retention_months: 24,
    };
    let pool = sipora_data::pg::connect_pool(&cfg)
        .await
        .expect("connect");
    sipora_data::pg::verify_provisioning_schema(&pool)
        .await
        .expect("schema");
    let state = Arc::new(store::AppState {
        domain: DOMAIN.into(),
        api_bearer_token: Some(TOKEN.into()),
        store: store::ApiStore::Postgres(pool),
        store_kind: store::DataStoreKind::Postgres,
    });
    let app = router(state);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}
