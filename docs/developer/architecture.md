# Architecture notes

**Authoritative** signaling scope and library boundaries for deployment and extension planning. Product-facing detail also appears in [services and binaries](/user/services-and-binaries) and [qualification](/qualification).

## `sipora-proxy` on UDP

The UDP proxy path is oriented toward **digest-authenticated REGISTER**, Redis-backed location, OPTIONS, and a **naive INVITE forward** (new `Via`, Request-URI rewrite toward the first registered contact). It is **not** a full RFC 3261 stateful proxy for INVITE on that path: the UDP loop focuses on requests and does not implement full response relay, `Record-Route`, or in-dialog routing for INVITE through the proxy alone.

For **end-to-end INVITE** where the client should see provisional and final responses from an upstream, use **`sipora-lb`** or **`sipora-b2bua`**, which map `Call-ID` to the client socket and relay responses from downstream peers.

## `sipora-sip` transaction layer

The `TransactionManager` and related client/server helpers under `crates/sipora-sip` are **library scaffolding** for experiments and future integration. They are **not** wired into `sipora-proxy` or `sipora-edge` today; do not assume RFC 3261 / RFC 6026 transaction completeness for deployed binaries until that integration is explicit and tested.

## Authentication and users

SIP digest REGISTER uses `users.sip_digest_ha1` in PostgreSQL. User creation normalizes username and domain to lowercase before computing HA1; verification compares digest responses with case-insensitive hex where needed for interoperability. Migrations and `sipora-auth` implement the stored form and verification policy in-tree.

## RFC interop backlog (default profile)

**Default target:** lab and lightweight edge/registrar deployments; media control often delegated out of process (for example RTPengine). **Not** IMS-core-complete unless explicitly scoped later.

Suggested order when extending SIP behavior:

1. If the product requires single-hop INVITE without lb/b2bua: **stateful UDP proxy** (responses, `Record-Route`, in-dialog methods) before other extensions.
2. **RFC 3263:** `_sip._udp` SRV (and NAPTR where needed) instead of plain host lookup only.
3. **RFC 3262:** `100rel` / PRACK when early reliable provisionals matter.
4. **RFC 4028:** session timers (`Session-Expires`, `Min-SE`).
5. **RFC 8760 / 7616:** digest algorithm and concurrent-credential alignment (deployment-specific today).
6. **RFC 7339:** overload signaling versus edge rate limits only.
7. **RFC 8224–8226:** STIR/PASSporT if PSTN-attested identity is required.
8. **RFC 5626 / 5627:** outbound connection reuse and GRUU-style addressing.
9. **ICE / mmusic:** signaling-only pieces where not fully delegated to the media plane (SDP offer/answer, ICE/trickle if not only via an external media controller).
