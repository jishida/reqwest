#[cfg(feature = "trust-dns")]
use trust_dns_resolver::config as trust_dns;

/// The lookup ip strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde-config", derive(Serialize, Deserialize))]
pub enum LookupIpStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6thenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6 (default)
    Ipv4thenIpv6,
}

impl Default for LookupIpStrategy {
    /// Returns Ipv4AndIpv6 as the default.
    fn default() -> Self {
        LookupIpStrategy::Ipv4thenIpv6
    }
}

#[cfg(feature = "trust-dns")]
impl Into<trust_dns::LookupIpStrategy> for LookupIpStrategy {
    fn into(self) -> trust_dns::LookupIpStrategy {
        match self {
            LookupIpStrategy::Ipv4Only => trust_dns::LookupIpStrategy::Ipv4Only,
            LookupIpStrategy::Ipv6Only => trust_dns::LookupIpStrategy::Ipv6Only,
            LookupIpStrategy::Ipv4AndIpv6 => trust_dns::LookupIpStrategy::Ipv4AndIpv6,
            LookupIpStrategy::Ipv6thenIpv4 => trust_dns::LookupIpStrategy::Ipv6thenIpv4,
            LookupIpStrategy::Ipv4thenIpv6 => trust_dns::LookupIpStrategy::Ipv4thenIpv6,
        }
    }
}
