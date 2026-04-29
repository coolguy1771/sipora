# Deployment

## Helm

Chart **`sipora`** lives under **`deploy/helm/`** with values in `values.yaml`, `values-dev.yaml`, and `values-prod.yaml`. Templates set `SIPORA__*` environment variables and mount database URLs from secrets where applicable. Adjust values for your cluster and registry.

## Docker

Each published binary has a Dockerfile under **`deploy/docker/`** named `Dockerfile.<binary>`. CI builds these images without pushing; wire your registry and `docker push` (or equivalent) in your delivery pipeline.

## Configuration at deploy time

Runtime behavior is entirely driven by merged `SiporaConfig` (files + environment). See [configuration](/configuration) and [configuration files](/user/configuration-files).
