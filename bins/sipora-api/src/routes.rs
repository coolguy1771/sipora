use crate::store::{self, AppState};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sipora_data::cdr::CdrRecord;
use sipora_data::pg::CdrSearchParams;
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    /// `postgres` or `mock` (see `SIPORA_API_MOCK_STORE`).
    pub data_store: String,
}

#[derive(Deserialize, ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CdrQuery {
    pub correlation_id: Option<String>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CdrQuerySnapshot {
    pub correlation_id: Option<String>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CdrListResponse {
    pub records: Vec<CdrRecord>,
    pub query: CdrQuerySnapshot,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserRequest {
    pub username: String,
    pub domain: String,
    pub password: String,
    pub enabled: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub domain: String,
    pub enabled: bool,
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "OK", body = HealthResponse),
    ),
    tag = "health"
)]
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let data_store = match state.store_kind {
        store::DataStoreKind::Postgres => "postgres",
        store::DataStoreKind::Mock => "mock",
    };
    Json(HealthResponse {
        status: "healthy".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        data_store: data_store.into(),
    })
}

/// Readiness: PostgreSQL reachable when using the real store; mock store is always ready.
pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match &state.store {
        store::ApiStore::Postgres(pool) => match pool.acquire().await {
            Ok(conn) => {
                drop(conn);
                StatusCode::OK
            }
            Err(_) => StatusCode::SERVICE_UNAVAILABLE,
        },
        store::ApiStore::Mock(_) => StatusCode::OK,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/users",
    responses(
        (status = 200, description = "List", body = [UserResponse]),
        (status = 500, description = "Server error"),
    ),
    tag = "users"
)]
pub async fn list_users(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match store::dispatch_list_users(&state).await {
        Ok(rows) => {
            let out: Vec<UserResponse> = rows.into_iter().map(user_summary_to_response).collect();
            Json(out).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/users",
    request_body = UserRequest,
    responses(
        (status = 201, description = "Created", body = UserResponse),
        (status = 400, description = "Bad request"),
        (status = 409, description = "Conflict"),
        (status = 500, description = "Server error"),
    ),
    tag = "users"
)]
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UserRequest>,
) -> impl IntoResponse {
    if req.username.is_empty() || req.domain.is_empty() || req.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "username, domain, and password are required" })),
        )
            .into_response();
    }
    if req.domain != state.domain {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "domain must match configured general.domain",
                "expected": state.domain,
            })),
        )
            .into_response();
    }
    let enabled = req.enabled.unwrap_or(true);
    match store::dispatch_create_user(&state, &req.username, &req.domain, &req.password, enabled)
        .await
    {
        Ok(row) => (StatusCode::CREATED, Json(user_summary_to_response(row))).into_response(),
        Err(sipora_data::DataError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/users/{id}",
    params(
        ("id" = String, Path, description = "User id (UUID)"),
    ),
    responses(
        (status = 200, description = "Found", body = UserResponse),
        (status = 400, description = "Invalid id"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Server error"),
    ),
    tag = "users"
)]
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Ok(uid) = uuid::Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid user id" })),
        )
            .into_response();
    };
    match store::dispatch_get_user(&state, uid).await {
        Ok(Some(row)) => Json(user_summary_to_response(row)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/cdrs",
    params(CdrQuery),
    responses(
        (status = 200, description = "Search results", body = CdrListResponse),
        (status = 400, description = "Bad query"),
        (status = 500, description = "Server error"),
    ),
    tag = "cdrs"
)]
pub async fn query_cdrs(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CdrQuery>,
) -> impl IntoResponse {
    let params = match cdr_params_from_query(&q) {
        Ok(p) => p,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response();
        }
    };
    match store::dispatch_search_cdrs(&state, &params).await {
        Ok(records) => Json(CdrListResponse {
            records,
            query: CdrQuerySnapshot {
                correlation_id: q.correlation_id.clone(),
                from_uri: q.from_uri.clone(),
                to_uri: q.to_uri.clone(),
                from_date: q.from_date.clone(),
                to_date: q.to_date.clone(),
            },
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn user_summary_to_response(u: sipora_data::pg::UserSummary) -> UserResponse {
    UserResponse {
        id: u.id.to_string(),
        username: u.username,
        domain: u.domain,
        enabled: u.enabled,
    }
}

fn cdr_params_from_query(q: &CdrQuery) -> Result<CdrSearchParams, String> {
    let correlation_id = match &q.correlation_id {
        None => None,
        Some(s) if s.is_empty() => None,
        Some(s) => {
            Some(uuid::Uuid::parse_str(s).map_err(|_| "invalid correlation_id".to_string())?)
        }
    };
    let from_date = parse_optional_ts(&q.from_date)?;
    let to_date = parse_optional_ts(&q.to_date)?;
    Ok(CdrSearchParams {
        correlation_id,
        from_uri: q.from_uri.clone(),
        to_uri: q.to_uri.clone(),
        from_date,
        to_date,
    })
}

fn parse_optional_ts(s: &Option<String>) -> Result<Option<DateTime<Utc>>, String> {
    match s {
        None => Ok(None),
        Some(x) if x.is_empty() => Ok(None),
        Some(x) => DateTime::parse_from_rfc3339(x)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|_| "from_date/to_date must be RFC3339".to_string()),
    }
}
