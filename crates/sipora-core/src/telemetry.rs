use anyhow::{Context, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use std::time::Duration;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub struct TelemetryGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    logger_provider: SdkLoggerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(e) = self.tracer_provider.shutdown() {
            eprintln!("tracer shutdown error: {e}");
        }
        if let Err(e) = self.meter_provider.shutdown() {
            eprintln!("meter shutdown error: {e}");
        }
        if let Err(e) = self.logger_provider.shutdown() {
            eprintln!("logger shutdown error: {e}");
        }
    }
}

pub fn init_telemetry(
    service_name: &str,
    otlp_endpoint: &str,
    metrics_interval_s: u64,
    success_sample_rate: f64,
) -> Result<TelemetryGuard> {
    let resource = Resource::builder()
        .with_attributes([
            KeyValue::new("service.name", service_name.to_owned()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ])
        .build();

    let tracer_provider =
        build_tracer_provider(otlp_endpoint, resource.clone(), success_sample_rate)?;
    let meter_provider = build_meter_provider(otlp_endpoint, resource.clone(), metrics_interval_s)?;
    let logger_provider = build_logger_provider(otlp_endpoint, resource)?;

    global::set_tracer_provider(tracer_provider.clone());
    global::set_meter_provider(meter_provider.clone());

    let tracer = tracer_provider.tracer(service_name.to_owned());
    let otel_trace_layer = OpenTelemetryLayer::new(tracer);
    let otel_log_layer = OpenTelemetryTracingBridge::new(&logger_provider);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_trace_layer)
        .with(otel_log_layer)
        .init();

    Ok(TelemetryGuard {
        tracer_provider,
        meter_provider,
        logger_provider,
    })
}

fn build_tracer_provider(
    endpoint: &str,
    resource: Resource,
    success_sample_rate: f64,
) -> Result<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .context("failed to build span exporter")?;

    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(success_sample_rate)));

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(sampler)
        .with_batch_exporter(exporter)
        .build();

    Ok(provider)
}

fn build_meter_provider(
    endpoint: &str,
    resource: Resource,
    interval_s: u64,
) -> Result<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .context("failed to build metric exporter")?;

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(interval_s))
        .build();

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    Ok(provider)
}

fn build_logger_provider(endpoint: &str, resource: Resource) -> Result<SdkLoggerProvider> {
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .context("failed to build log exporter")?;

    let provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    Ok(provider)
}
