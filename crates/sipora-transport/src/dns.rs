use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use moka::Expiry;
use moka::future::Cache;
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
        ttl: Duration::from_secs(u64::MAX / 2),
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

async fn lookup_ip(host: &str) -> Option<hickory_resolver::lookup_ip::LookupIp> {
    timeout(DNS_TIMEOUT, resolver()?.lookup_ip(host))
        .await
        .ok()?
        .ok()
}

fn resolver() -> Option<&'static TokioResolver> {
    RESOLVER
        .get_or_init(|| {
            TokioResolver::builder_tokio()
                .ok()
                .and_then(|builder| builder.build().ok())
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

fn sort_srv_records(records: &mut [(u16, u16, u16, String)]) {
    records.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
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
    fn sorts_srv_records_by_priority_then_weight() {
        let mut records = vec![
            (20, 100, 5060, "late.example.com".to_string()),
            (10, 1, 5060, "low.example.com".to_string()),
            (10, 10, 5060, "high.example.com".to_string()),
        ];

        sort_srv_records(&mut records);

        assert_eq!(records[0].3, "high.example.com");
        assert_eq!(records[1].3, "low.example.com");
        assert_eq!(records[2].3, "late.example.com");
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
