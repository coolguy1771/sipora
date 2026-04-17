use crate::routes::{
    CdrListResponse, CdrQuery, CdrQuerySnapshot, HealthResponse, UserRequest, UserResponse,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(title = "Sipora provisioning API", version = env!("CARGO_PKG_VERSION")),
    paths(
        crate::routes::health,
        crate::routes::list_users,
        crate::routes::create_user,
        crate::routes::get_user,
        crate::routes::query_cdrs,
    ),
    components(schemas(
        HealthResponse,
        UserRequest,
        UserResponse,
        CdrQuery,
        CdrQuerySnapshot,
        CdrListResponse,
        sipora_data::cdr::CdrRecord,
    )),
    tags(
        (name = "health", description = "Liveness"),
        (name = "users", description = "Provisioning users"),
        (name = "cdrs", description = "Call detail records"),
    )
)]
pub struct ApiDoc;
