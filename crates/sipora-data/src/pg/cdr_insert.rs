use crate::DataError;
use crate::cdr::CdrRecord;
use sqlx::PgPool;

/// Inserts one CDR row into the partitioned `cdr` table (`setup_at` must fall in an existing partition).
pub async fn insert_cdr(pool: &PgPool, rec: &CdrRecord) -> Result<(), DataError> {
    let leg_s = rec.leg.to_string();
    let duration = rec.duration_s.map(|d| d as i32);
    let rc = i16::try_from(rec.result_code)
        .map_err(|_| DataError::Serialization("result_code".into()))?;

    sqlx::query(
        r#"
        INSERT INTO cdr (
            id, correlation_id, leg, from_uri, to_uri, setup_at, answered_at, ended_at,
            duration_s, result_code, codec, rtp_loss_pct, rtp_jitter_ms, srtp_cipher,
            media_ip, proxy_node, hash_chain
        ) VALUES (
            $1, $2, $3::char(1), $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
            $15::inet, $16, $17
        )
        "#,
    )
    .bind(rec.id)
    .bind(rec.correlation_id)
    .bind(&leg_s)
    .bind(&rec.from_uri)
    .bind(&rec.to_uri)
    .bind(rec.setup_at)
    .bind(rec.answered_at)
    .bind(rec.ended_at)
    .bind(duration)
    .bind(rc)
    .bind(&rec.codec)
    .bind(rec.rtp_loss_pct)
    .bind(rec.rtp_jitter_ms)
    .bind(&rec.srtp_cipher)
    .bind(rec.media_ip.as_deref())
    .bind(&rec.proxy_node)
    .bind(&rec.hash_chain)
    .execute(pool)
    .await
    .map_err(|e| DataError::Database(e.to_string()))?;
    Ok(())
}
