# Observability

## OpenTelemetry

Binaries call `sipora_core::telemetry::init_telemetry` with OTLP endpoint and sampling driven from the **`telemetry`** section of shared configuration. Set endpoints and sampling policy there (or via `SIPORA__TELEMETRY__*` overrides) so traces and metrics reach your collector.

## Local Grafana stack

For lab-style integration, **`tests/docker-compose.yml`** can wire Grafana Alloy to Mimir, Tempo, and Loki. Dashboards and alerting rules live under **`deploy/grafana/`** in the repository.

Compose layout and optional services evolve with the tree; start from that file when reproducing local telemetry.
