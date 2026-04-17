//! Optional Kafka producer for CDR JSON export.

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

use crate::{DataError, Result};

pub fn producer(brokers_csv: &str) -> Result<FutureProducer> {
    ClientConfig::new()
        .set("bootstrap.servers", brokers_csv)
        .set("message.timeout.ms", "5000")
        .create()
        .map_err(|e| DataError::Kafka(e.to_string()))
}

pub async fn publish_json(prod: &FutureProducer, topic: &str, key: &str, json: &str) -> Result<()> {
    let rec = FutureRecord::to(topic).key(key).payload(json.as_bytes());
    prod.send(rec, Duration::from_secs(8))
        .await
        .map_err(|(e, _)| DataError::Kafka(e.to_string()))?;
    Ok(())
}

pub fn brokers_csv(brokers: &[String]) -> Option<String> {
    if brokers.is_empty() {
        return None;
    }
    Some(brokers.join(","))
}
