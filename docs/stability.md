# Stability and versioning

The workspace is **0.x** until an explicit **1.0.0** release. Semantic versioning applies to published artifacts (crates or container tags) once this project adopts them.

## Release tiers (target for 1.0.0)

| Tier | Binaries / crates | Expectation at 1.0 |
|------|-------------------|--------------------|
| **GA** | `sipora-proxy`, `sipora-edge`, `sipora-lb`, `sipora-api`, `sipora-b2bua` | Listen on configured ports; behavior covered by CI and [qualification](qualification.md) checks. `sipora-b2bua` requires `[b2bua].downstream` and relays SIP over UDP (INVITE SDP filtered by codec policy; other in-dialog requests relayed like the load balancer). |
| **Libraries** | `sipora-core`, `sipora-sip`, `sipora-sdp`, `sipora-transport`, `sipora-auth`, `sipora-data`, `sipora-media`, `sipora-location`, `sipora-edge` | Public error types use `#[non_exhaustive]` so new variants can ship in minor releases. Other `pub` API may still change before 1.0. |

## Error types

Public `*Error` enums in workspace crates are marked `#[non_exhaustive]`. Downstream code should always include a catch-all arm when matching.

## Crates.io

Crates are currently consumed via workspace `path` dependencies. Publishing to crates.io, if added later, should follow the same semver rules and changelog entries described in [RELEASING.md](RELEASING.md).
