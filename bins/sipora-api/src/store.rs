use chrono::Utc;
use sipora_data::cdr::CdrRecord;
use sipora_data::pg::{
    CdrSearchParams, UserSummary, create_user as db_create_user, get_user_by_id,
    list_users as db_list_users, search_cdrs,
};
use sipora_data::{DataError, PgPool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DataStoreKind {
    Postgres,
    Mock,
}

pub enum ApiStore {
    Postgres(PgPool),
    Mock(Arc<Mutex<MockData>>),
}

/// Ephemeral user map for `SIPORA_API_MOCK_STORE` / `--mock-store` only.
pub struct MockData {
    users_by_id: HashMap<Uuid, UserSummary>,
    aor_to_id: HashMap<(String, String), Uuid>,
}

impl MockData {
    fn new() -> Self {
        Self {
            users_by_id: HashMap::new(),
            aor_to_id: HashMap::new(),
        }
    }

    fn list_users(&self, domain: &str) -> Vec<UserSummary> {
        let mut v: Vec<UserSummary> = self
            .users_by_id
            .values()
            .filter(|u| u.domain == domain)
            .cloned()
            .collect();
        v.sort_by_key(|u| std::cmp::Reverse(u.created_at));
        v
    }

    fn get_user(&self, id: Uuid, domain: &str) -> Option<UserSummary> {
        self.users_by_id
            .get(&id)
            .filter(|u| u.domain == domain)
            .cloned()
    }

    fn create_user(
        &mut self,
        username: &str,
        domain: &str,
        _password: &str,
        enabled: bool,
    ) -> Result<UserSummary, DataError> {
        let key = (username.to_string(), domain.to_string());
        if self.aor_to_id.contains_key(&key) {
            return Err(DataError::Conflict("user already exists".into()));
        }
        let id = Uuid::new_v4();
        let summary = UserSummary {
            id,
            username: username.to_string(),
            domain: domain.to_string(),
            enabled,
            created_at: Utc::now(),
        };
        self.users_by_id.insert(id, summary.clone());
        self.aor_to_id.insert(key, id);
        Ok(summary)
    }
}

pub struct AppState {
    pub domain: String,
    pub api_bearer_token: Option<String>,
    pub store: ApiStore,
    pub store_kind: DataStoreKind,
}

pub async fn dispatch_list_users(state: &AppState) -> Result<Vec<UserSummary>, DataError> {
    match &state.store {
        ApiStore::Postgres(p) => db_list_users(p, &state.domain).await,
        ApiStore::Mock(m) => Ok(m.lock().await.list_users(&state.domain)),
    }
}

pub async fn dispatch_get_user(
    state: &AppState,
    id: Uuid,
) -> Result<Option<UserSummary>, DataError> {
    match &state.store {
        ApiStore::Postgres(p) => get_user_by_id(p, id, &state.domain).await,
        ApiStore::Mock(m) => Ok(m.lock().await.get_user(id, &state.domain)),
    }
}

pub async fn dispatch_create_user(
    state: &AppState,
    username: &str,
    domain: &str,
    password: &str,
    enabled: bool,
) -> Result<UserSummary, DataError> {
    match &state.store {
        ApiStore::Postgres(p) => db_create_user(p, username, domain, password, enabled).await,
        ApiStore::Mock(m) => m
            .lock()
            .await
            .create_user(username, domain, password, enabled),
    }
}

pub async fn dispatch_search_cdrs(
    state: &AppState,
    params: &CdrSearchParams,
) -> Result<Vec<CdrRecord>, DataError> {
    match &state.store {
        ApiStore::Postgres(p) => search_cdrs(p, params).await,
        ApiStore::Mock(_) => Ok(Vec::new()),
    }
}

pub fn new_mock_store() -> ApiStore {
    ApiStore::Mock(Arc::new(Mutex::new(MockData::new())))
}
