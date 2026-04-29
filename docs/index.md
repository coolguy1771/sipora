---
layout: home

hero:
  name: Sipora
  text: SIP platform documentation
  tagline: Canonical reference for services, configuration, qualification, and development.
  actions:
    - theme: brand
      text: User guide
      link: /user/overview
    - theme: alt
      text: Developer guide
      link: /developer/workspace

features:
  - title: Operators
    details: Requirements, quickstart, binaries, config files, database migrations, observability, and deployment paths.
  - title: Integrators
    details: Single SiporaConfig model, environment overrides, Helm and Docker layouts, and qualification checklists.
  - title: Contributors
    details: Workspace layout, CI matrix, architecture boundaries, and how to build these docs.
---

## Canonical source

**This site is authoritative.** Product behavior, supported versions (Postgres 18, Valkey 9), CLI and HTTP semantics, migration flow, and release process are documented here. The repository root `README.md` is intentionally short and points to this tree so information does not drift across multiple top-level documents.

Start with [user overview](/user/overview) or [quickstart](/user/quickstart); use the left sidebar for the full map. Legal and changelog policy: [license](/project/license), [changelog](/project/changelog).
