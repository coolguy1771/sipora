use crate::DataError;
use crate::cdr::CdrRecord;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

pub struct CdrSearchParams {
    pub correlation_id: Option<Uuid>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

pub async fn search_cdrs(
    pool: &PgPool,
    params: &CdrSearchParams,
) -> Result<Vec<CdrRecord>, DataError> {
    let mut b: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"SELECT id, correlation_id, leg::text AS leg, from_uri, to_uri,
           setup_at, answered_at, ended_at, duration_s, result_code::int4 AS result_code,
           codec, rtp_loss_pct::float8 AS rtp_loss_pct, rtp_jitter_ms::float8 AS rtp_jitter_ms,
           srtp_cipher, media_ip::text AS media_ip, proxy_node, hash_chain
           FROM cdr WHERE 1 = 1 "#,
    );
    if let Some(cid) = params.correlation_id {
        b.push(" AND correlation_id = ");
        b.push_bind(cid);
    }
    if let Some(ref from) = params.from_uri {
        b.push(" AND from_uri = ");
        b.push_bind(from);
    }
    if let Some(ref to) = params.to_uri {
        b.push(" AND to_uri = ");
        b.push_bind(to);
    }
    if let Some(t) = params.from_date {
        b.push(" AND setup_at >= ");
        b.push_bind(t);
    }
    if let Some(t) = params.to_date {
        b.push(" AND setup_at <= ");
        b.push_bind(t);
    }
    b.push(" ORDER BY setup_at DESC LIMIT 500");
    let rows = b
        .build_query_as::<CdrRow>()
        .fetch_all(pool)
        .await
        .map_err(|e| DataError::Database(e.to_string()))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(cdr_row_to_record(row)?);
    }
    Ok(out)
}

#[derive(sqlx::FromRow)]
struct CdrRow {
    id: Uuid,
    correlation_id: Uuid,
    leg: String,
    from_uri: String,
    to_uri: String,
    setup_at: DateTime<Utc>,
    answered_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
    duration_s: Option<i32>,
    result_code: i32,
    codec: Option<String>,
    rtp_loss_pct: Option<f64>,
    rtp_jitter_ms: Option<f64>,
    srtp_cipher: Option<String>,
    media_ip: Option<String>,
    proxy_node: Option<String>,
    hash_chain: Option<String>,
}

fn cdr_row_to_record(row: CdrRow) -> Result<CdrRecord, DataError> {
    let leg = row
        .leg
        .chars()
        .next()
        .ok_or_else(|| DataError::Serialization("cdr leg".into()))?;
    let result_code = u16::try_from(row.result_code)
        .map_err(|_| DataError::Serialization(format!("cdr result_code {}", row.result_code)))?;
    Ok(CdrRecord {
        id: row.id,
        correlation_id: row.correlation_id,
        leg,
        from_uri: row.from_uri,
        to_uri: row.to_uri,
        setup_at: row.setup_at,
        answered_at: row.answered_at,
        ended_at: row.ended_at,
        duration_s: row.duration_s.map(|x| x as i64),
        result_code,
        codec: row.codec,
        rtp_loss_pct: row.rtp_loss_pct,
        rtp_jitter_ms: row.rtp_jitter_ms,
        srtp_cipher: row.srtp_cipher,
        media_ip: row.media_ip,
        proxy_node: row.proxy_node,
        hash_chain: row.hash_chain,
    })
}
