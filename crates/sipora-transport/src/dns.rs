use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use moka::Expiry;
use moka::future::Cache;
use rand::RngExt;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SipTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipTarget {
    pub addr: SocketAddr,
    pub transport: SipTransport,
    pub from_srv: bool,
}

#[derive(Debug, Clone)]
struct CachedTargets {
    ttl: Duration,
    targets: Vec<SipTarget>,
}

struct TargetExpiry;

impl Expiry<String, CachedTargets> for TargetExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CachedTargets,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &CachedTargets,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

#[derive(Debug, Clone)]
struct ResolveResult {
    targets: Vec<SipTarget>,
    ttl: Duration,
}

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const MIN_CACHE_TTL: Duration = Duration::from_secs(1);
const MAX_TARGET_CACHE_SIZE: u64 = 4096;

/// Upper bound for merging TTLs when aggregating SRV host lookups.
const RESOLVE_AGGREGATE_TTL_CAP: Duration = Duration::from_secs(u64::MAX / 2);

static DNS_CACHE: OnceLock<Cache<String, CachedTargets>> = OnceLock::new();
static RESOLVER: OnceLock<Option<TokioResolver>> = OnceLock::new();

pub async fn resolve_sip_targets(
    domain: &str,
    port_hint: Option<u16>,
    transport_hint: SipTransport,
) -> Vec<SipTarget> {
    let key = cache_key(domain, port_hint, transport_hint);
    if let Some(cached) = cache().get(&key).await {
        return cached.targets;
    }

    let result = resolve_uncached(domain, port_hint, transport_hint).await;
    if !result.targets.is_empty() {
        cache()
            .insert(
                key,
                CachedTargets {
                    ttl: result.ttl.max(MIN_CACHE_TTL),
                    targets: result.targets.clone(),
                },
            )
            .await;
    }
    result.targets
}

async fn resolve_uncached(
    domain: &str,
    port_hint: Option<u16>,
    transport_hint: SipTransport,
) -> ResolveResult {
    if let Ok(ip) = domain.parse::<IpAddr>() {
        return ip_target(ip, port_hint, transport_hint);
    }

    if let Some(port) = port_hint {
        return resolve_host_addrs(domain, port, transport_hint, false).await;
    }

    resolve_via_dns_discovery(domain, transport_hint).await
}

async fn resolve_via_dns_discovery(domain: &str, transport: SipTransport) -> ResolveResult {
    let (srv_name, naptr_ttl) = naptr_srv_name(domain, transport)
        .await
        .map(|(name, ttl)| (name, Some(ttl)))
        .unwrap_or_else(|| (default_srv_name(domain, transport), None));

    let mut srv_result = resolve_srv_targets(&srv_name, transport).await;
    if let Some(ttl) = naptr_ttl {
        srv_result.ttl = srv_result.ttl.min(ttl);
    }

    if srv_result.targets.is_empty() {
        resolve_host_addrs(domain, default_port(transport), transport, false).await
    } else {
        srv_result
    }
}

fn ip_target(ip: IpAddr, port_hint: Option<u16>, transport: SipTransport) -> ResolveResult {
    ResolveResult {
        targets: vec![SipTarget {
            addr: SocketAddr::new(ip, port_hint.unwrap_or(default_port(transport))),
            transport,
            from_srv: false,
        }],
        ttl: MIN_CACHE_TTL,
    }
}

async fn naptr_srv_name(domain: &str, transport: SipTransport) -> Option<(String, Duration)> {
    let service = naptr_service(transport);
    let lookup = lookup_records(domain, RecordType::NAPTR).await?;
    let ttl = ttl_until(lookup.valid_until());
    let mut naptrs = Vec::new();

    for record in lookup.answers() {
        let RData::NAPTR(naptr) = &record.data else {
            continue;
        };
        let record_service = String::from_utf8_lossy(&naptr.services);
        if record_service.eq_ignore_ascii_case(service) {
            naptrs.push((
                naptr.order,
                naptr.preference,
                name_to_host(&naptr.replacement),
            ));
        }
    }

    naptrs.sort_by_key(|(order, preference, _)| (*order, *preference));
    naptrs
        .into_iter()
        .map(|(_, _, replacement)| (replacement, ttl))
        .next()
}

async fn resolve_srv_targets(srv_name: &str, transport: SipTransport) -> ResolveResult {
    let Some(lookup) = lookup_records(srv_name, RecordType::SRV).await else {
        return empty_result();
    };

    let ttl = ttl_until(lookup.valid_until());
    let mut srvs = Vec::new();
    for record in lookup.answers() {
        if let RData::SRV(srv) = &record.data {
            srvs.push((
                srv.priority,
                srv.weight,
                srv.port,
                name_to_host(&srv.target),
            ));
        }
    }

    sort_srv_records(&mut srvs);
    let mut result = resolve_ordered_srv(srvs, transport).await;
    result.ttl = result.ttl.min(ttl);
    result
}

async fn resolve_ordered_srv(
    srvs: Vec<(u16, u16, u16, String)>,
    transport: SipTransport,
) -> ResolveResult {
    let mut result = ResolveResult {
        targets: Vec::new(),
        ttl: RESOLVE_AGGREGATE_TTL_CAP,
    };

    for (_, _, port, host) in srvs {
        let host_result = resolve_host_addrs(&host, port, transport, true).await;
        result.ttl = result.ttl.min(host_result.ttl);
        result.targets.extend(host_result.targets);
    }

    if result.targets.is_empty() {
        empty_result()
    } else {
        result
    }
}

async fn resolve_host_addrs(
    host: &str,
    port: u16,
    transport: SipTransport,
    from_srv: bool,
) -> ResolveResult {
    let Some(lookup) = lookup_ip(host).await else {
        return empty_result();
    };

    ResolveResult {
        ttl: ttl_until(lookup.valid_until()),
        targets: lookup
            .iter()
            .map(|ip| SipTarget {
                addr: SocketAddr::new(ip, port),
                transport,
                from_srv,
            })
            .collect(),
    }
}

async fn lookup_records(
    name: &str,
    record_type: RecordType,
) -> Option<hickory_resolver::lookup::Lookup> {
    timeout(DNS_TIMEOUT, resolver()?.lookup(name, record_type))
        .await
        .ok()?
        .ok()
}

/// Raw DNS lookup (ENUM/NAPTR tests and helpers).
pub async fn dns_lookup(
    name: &str,
    record_type: RecordType,
) -> Option<hickory_resolver::lookup::Lookup> {
    lookup_records(name, record_type).await
}

async fn lookup_ip(host: &str) -> Option<hickory_resolver::lookup_ip::LookupIp> {
    timeout(DNS_TIMEOUT, resolver()?.lookup_ip(host))
        .await
        .ok()?
        .ok()
}

fn resolver() -> Option<&'static TokioResolver> {
    RESOLVER
        .get_or_init(|| match TokioResolver::builder_tokio() {
            Ok(builder) => match builder.build() {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to initialize TokioResolver (build)"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "failed to initialize TokioResolver (builder_tokio)"
                );
                None
            }
        })
        .as_ref()
}

fn cache() -> &'static Cache<String, CachedTargets> {
    DNS_CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(MAX_TARGET_CACHE_SIZE)
            .expire_after(TargetExpiry)
            .build()
    })
}

fn empty_result() -> ResolveResult {
    ResolveResult {
        targets: Vec::new(),
        ttl: MIN_CACHE_TTL,
    }
}

fn ttl_until(valid_until: Instant) -> Duration {
    valid_until
        .checked_duration_since(Instant::now())
        .unwrap_or(MIN_CACHE_TTL)
        .max(MIN_CACHE_TTL)
}

fn name_to_host(name: &hickory_resolver::proto::rr::Name) -> String {
    name.to_utf8().trim_end_matches('.').to_string()
}

fn default_srv_name(domain: &str, transport: SipTransport) -> String {
    match transport {
        SipTransport::Udp => format!("_sip._udp.{domain}"),
        SipTransport::Tcp => format!("_sip._tcp.{domain}"),
        SipTransport::Tls => format!("_sips._tcp.{domain}"),
    }
}

fn naptr_service(transport: SipTransport) -> &'static str {
    match transport {
        SipTransport::Udp => "SIP+D2U",
        SipTransport::Tcp => "SIP+D2T",
        SipTransport::Tls => "SIPS+D2T",
    }
}

fn default_port(transport: SipTransport) -> u16 {
    match transport {
        SipTransport::Tls => 5061,
        SipTransport::Udp | SipTransport::Tcp => 5060,
    }
}

/// Orders SRV tuples by priority (RFC 2782), then per-priority group:
/// zero-weight records first, then weighted random order for non-zero weights.
fn sort_srv_records(records: &mut [(u16, u16, u16, String)]) {
    if records.is_empty() {
        return;
    }
    let input = records.to_vec();
    let mut priorities: Vec<u16> = input.iter().map(|(p, _, _, _)| *p).collect();
    priorities.sort_unstable();
    priorities.dedup();

    let mut out = Vec::with_capacity(input.len());
    for pri in priorities {
        let group: Vec<_> = input
            .iter()
            .filter(|(p, _, _, _)| *p == pri)
            .cloned()
            .collect();
        out.extend(reorder_srv_priority_group(group));
    }
    for (i, rec) in out.into_iter().enumerate() {
        records[i] = rec;
    }
}

fn reorder_srv_priority_group(
    records: Vec<(u16, u16, u16, String)>,
) -> Vec<(u16, u16, u16, String)> {
    let mut zeros = Vec::new();
    let mut weighted = Vec::new();
    for rec in records {
        if rec.1 == 0 {
            zeros.push(rec);
        } else {
            weighted.push(rec);
        }
    }
    let mut rng = rand::rng();
    let mut out = zeros;
    while !weighted.is_empty() {
        let sum: u32 = weighted.iter().map(|(_, w, _, _)| *w as u32).sum();
        if sum == 0 {
            out.append(&mut weighted);
            break;
        }
        let pick = rng.random_range(0..sum);
        let mut acc = 0u32;
        let idx = weighted
            .iter()
            .enumerate()
            .find_map(|(i, (_, w, _, _))| {
                acc += *w as u32;
                (acc > pick).then_some(i)
            })
            .unwrap_or(0);
        out.push(weighted.remove(idx));
    }
    out
}

fn cache_key(domain: &str, port: Option<u16>, transport: SipTransport) -> String {
    format!("{}:{:?}:{:?}", domain.to_ascii_lowercase(), port, transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_ip_literal_with_default_udp_port() {
        let targets = resolve_sip_targets("127.0.0.1", None, SipTransport::Udp).await;

        assert!(targets.iter().any(|target| target.addr.port() == 5060));
        assert!(targets.iter().all(|target| !target.from_srv));
    }

    #[tokio::test]
    async fn resolves_ip_literal_with_port_hint() {
        let targets = resolve_sip_targets("127.0.0.1", Some(5070), SipTransport::Udp).await;

        assert_eq!(targets[0].addr.port(), 5070);
        assert_eq!(targets[0].transport, SipTransport::Udp);
    }

    #[test]
    fn sorts_srv_by_ascending_priority_value() {
        let mut records = vec![
            (20, 50, 5060, "pri20.example.com".to_string()),
            (10, 50, 5060, "pri10.example.com".to_string()),
        ];

        sort_srv_records(&mut records);

        assert_eq!(records[0].0, 10);
        assert_eq!(records[1].0, 20);
    }

    #[test]
    fn sorts_srv_zero_weight_before_nonzero_in_priority_group() {
        let mut records = vec![
            (10, 5, 5060, "w5.example.com".to_string()),
            (10, 0, 5060, "z0.example.com".to_string()),
            (10, 8, 5060, "w8.example.com".to_string()),
        ];

        sort_srv_records(&mut records);

        assert_eq!(records[0].3, "z0.example.com");
    }

    #[test]
    fn sorts_srv_same_priority_preserves_multiset() {
        let mut records = vec![
            (10, 3, 5060, "a.example.com".to_string()),
            (10, 3, 5060, "b.example.com".to_string()),
            (10, 3, 5060, "c.example.com".to_string()),
        ];
        let mut before: Vec<_> = records.iter().map(|(_, _, _, h)| h.clone()).collect();
        before.sort();

        sort_srv_records(&mut records);

        let mut after: Vec<_> = records.iter().map(|(_, _, _, h)| h.clone()).collect();
        after.sort();
        assert_eq!(after, before);
    }

    #[test]
    fn builds_default_srv_names() {
        assert_eq!(
            default_srv_name("example.com", SipTransport::Udp),
            "_sip._udp.example.com"
        );
        assert_eq!(
            default_srv_name("example.com", SipTransport::Tcp),
            "_sip._tcp.example.com"
        );
        assert_eq!(
            default_srv_name("example.com", SipTransport::Tls),
            "_sips._tcp.example.com"
        );
    }

    #[test]
    fn maps_naptr_services() {
        assert_eq!(naptr_service(SipTransport::Udp), "SIP+D2U");
        assert_eq!(naptr_service(SipTransport::Tcp), "SIP+D2T");
        assert_eq!(naptr_service(SipTransport::Tls), "SIPS+D2T");
    }
}
