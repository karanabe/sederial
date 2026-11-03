//! Validated upstream groups, local A policy and longest-label-suffix selection.
//!
//! Routing depends only on the question name. Record types, network failures
//! and upstream health do not change which local rule or group is eligible.

use crate::dns::DomainName;
use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, SocketAddr},
};

pub(crate) const MAX_UPSTREAMS: usize = 8;

/// A concrete unicast endpoint with a nonzero port and canonical IPv4 spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UpstreamAddress(SocketAddr);
impl UpstreamAddress {
    /// Normalizes IPv4-mapped IPv6 while retaining native IPv6 scope information.
    ///
    /// # Errors
    /// Rejects unspecified, multicast and IPv4 broadcast addresses, and port zero.
    pub(crate) fn new(address: SocketAddr) -> Result<Self, RouteError> {
        // IPv4-mapped IPv6 denotes the same endpoint as its IPv4 form.
        let ip = address.ip().to_canonical();
        let address = if ip.is_ipv4() {
            SocketAddr::new(ip, address.port())
        } else {
            address // Preserve scope IDs for native IPv6 endpoints.
        };
        if address.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip == std::net::Ipv4Addr::BROADCAST
        {
            return Err(RouteError::InvalidAddress);
        }
        Ok(Self(address))
    }
    pub(crate) fn socket(self) -> SocketAddr {
        self.0
    }
}
impl fmt::Display for UpstreamAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A nonempty, bounded list of distinct endpoints in configured failover order.
#[derive(Debug)]
pub(crate) struct UpstreamGroup(Vec<UpstreamAddress>);
impl UpstreamGroup {
    /// Validates group size and uniqueness without reordering endpoints.
    ///
    /// # Errors
    /// Rejects empty groups, groups larger than [`MAX_UPSTREAMS`], and duplicates.
    pub(crate) fn new(addresses: Vec<UpstreamAddress>) -> Result<Self, RouteError> {
        if addresses.is_empty() || addresses.len() > MAX_UPSTREAMS {
            return Err(RouteError::InvalidGroupSize);
        }
        for (i, address) in addresses.iter().enumerate() {
            if addresses[..i].contains(address) {
                return Err(RouteError::DuplicateServer);
            }
        }
        Ok(Self(addresses))
    }
    /// Returns endpoints in the order in which forwarding should try them.
    pub(crate) fn servers(&self) -> &[UpstreamAddress] {
        &self.0
    }
}

/// A suffix policy covering both the suffix itself and all its subdomains.
#[derive(Debug)]
pub(crate) struct Route {
    pub(crate) suffix: DomainName,
    pub(crate) upstreams: UpstreamGroup,
}

/// A local IN A answer for a suffix and every name below it.
#[derive(Debug)]
pub(crate) struct LocalRecord {
    pub(crate) suffix: DomainName,
    pub(crate) address: Ipv4Addr,
    pub(crate) ttl: u32,
}

/// Immutable policy with unique suffixes ordered from most to least specific.
#[derive(Debug)]
pub(crate) struct RoutingTable {
    default: Option<UpstreamGroup>,
    routes: Vec<Route>,
    local: Vec<LocalRecord>,
}
/// A borrowed route decision, retaining whether an explicit suffix matched.
pub(crate) enum Selection<'a> {
    Default(&'a UpstreamGroup),
    Routed(&'a Route),
    Local(&'a LocalRecord),
    Unmatched,
}
impl RoutingTable {
    /// Rejects duplicate suffixes and prepares longest-suffix lookup order.
    ///
    /// # Errors
    /// Returns [`RouteError::DuplicateRoute`] for equivalent domain names,
    /// including differences only in ASCII case or a trailing presentation dot,
    /// and collisions between local and forwarding rules.
    pub(crate) fn new(
        default: Option<UpstreamGroup>,
        mut routes: Vec<Route>,
        mut local: Vec<LocalRecord>,
    ) -> Result<Self, RouteError> {
        for (i, route) in routes.iter().enumerate() {
            if routes[..i]
                .iter()
                .any(|previous| previous.suffix == route.suffix)
            {
                return Err(RouteError::DuplicateRoute(route.suffix.clone()));
            }
        }
        for (i, record) in local.iter().enumerate() {
            if local[..i]
                .iter()
                .any(|previous| previous.suffix == record.suffix)
                || routes.iter().any(|route| route.suffix == record.suffix)
            {
                return Err(RouteError::DuplicateRoute(record.suffix.clone()));
            }
        }
        // With complete-label matching, specificity is the number of labels,
        // not the number of bytes. The first matching route is then sufficient.
        routes.sort_by_key(|route| std::cmp::Reverse(route.suffix.label_count()));
        local.sort_by_key(|record| std::cmp::Reverse(record.suffix.label_count()));
        Ok(Self {
            default,
            routes,
            local,
        })
    }
    /// Selects the longest suffix, or the default only when no suffix matches.
    ///
    /// Exhausting a routed group never authorizes use of the default group;
    /// otherwise private names could leak to a public resolver during outages.
    /// Local rules also never fall back by record type. No match and no default
    /// yields `Unmatched`, allowing a local negative response without I/O.
    pub(crate) fn select(&self, name: &DomainName) -> Selection<'_> {
        let route = self
            .routes
            .iter()
            .find(|route| name.is_subdomain_of(&route.suffix));
        let local = self
            .local
            .iter()
            .find(|record| name.is_subdomain_of(&record.suffix));
        match (route, local) {
            (Some(route), Some(record))
                if route.suffix.label_count() > record.suffix.label_count() =>
            {
                Selection::Routed(route)
            }
            (_, Some(record)) => Selection::Local(record),
            (Some(route), None) => Selection::Routed(route),
            (None, None) => self
                .default
                .as_ref()
                .map_or(Selection::Unmatched, Selection::Default),
        }
    }
    /// Returns explicit routes in lookup order, rather than configuration order.
    pub(crate) fn routes(&self) -> &[Route] {
        &self.routes
    }
    pub(crate) fn default(&self) -> Option<&UpstreamGroup> {
        self.default.as_ref()
    }
    pub(crate) fn local(&self) -> &[LocalRecord] {
        &self.local
    }
    pub(crate) fn has_upstreams(&self) -> bool {
        self.default.is_some() || !self.routes.is_empty()
    }
}

/// Violations of endpoint, upstream-group or routing-table invariants.
#[derive(Debug)]
pub(crate) enum RouteError {
    InvalidAddress,
    InvalidGroupSize,
    DuplicateServer,
    DuplicateRoute(DomainName),
}
impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => {
                f.write_str("expected a unicast IP address with a nonzero port")
            }
            Self::InvalidGroupSize => {
                write!(f, "each upstream group needs 1..={MAX_UPSTREAMS} servers")
            }
            Self::DuplicateServer => f.write_str("duplicate upstream server"),
            Self::DuplicateRoute(name) => write!(f, "duplicate route for {name}"),
        }
    }
}
impl Error for RouteError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn group(port: u16) -> UpstreamGroup {
        UpstreamGroup::new(vec![
            UpstreamAddress::new(([127, 0, 0, 1], port).into()).unwrap(),
        ])
        .unwrap()
    }
    #[test]
    fn exact_subdomain_longest_boundary_default_and_reverse() {
        let routes = [
            "exceeds.test",
            "ad.lab.exceeds.test",
            "lab.exceeds.test",
            "100.168.192.in-addr.arpa",
        ]
        .iter()
        .enumerate()
        .map(|(i, name)| Route {
            suffix: name.parse().unwrap(),
            upstreams: group(100 + i as u16),
        })
        .collect();
        let table = RoutingTable::new(Some(group(53)), routes, vec![]).unwrap();
        for (name, port) in [
            ("ad.lab.exceeds.test", 101),
            ("HOST.AD.LAB.EXCEEDS.TEST.", 101),
            ("_ldap._tcp.dc._msdcs.ad.lab.exceeds.test", 101),
            ("lab.exceeds.test", 102),
            ("host.exceeds.test", 100),
            ("badexceeds.test", 53),
            ("example.com", 53),
            ("github.com", 53),
            ("1.100.168.192.in-addr.arpa", 103),
            (".", 53),
        ] {
            let group = match table.select(&name.parse().unwrap()) {
                Selection::Default(group) => group,
                Selection::Routed(route) => &route.upstreams,
                _ => panic!("expected forwarding"),
            };
            assert_eq!(group.servers()[0].socket().port(), port, "{name}");
        }
    }
    #[test]
    fn root_route_and_duplicate_normalization() {
        let table = RoutingTable::new(
            Some(group(53)),
            vec![Route {
                suffix: ".".parse().unwrap(),
                upstreams: group(54),
            }],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            table.select(&"anything.test".parse().unwrap()),
            Selection::Routed(_)
        ));
        assert!(
            RoutingTable::new(
                Some(group(53)),
                vec![
                    Route {
                        suffix: "EXAMPLE.COM".parse().unwrap(),
                        upstreams: group(54)
                    },
                    Route {
                        suffix: "example.com.".parse().unwrap(),
                        upstreams: group(55)
                    }
                ],
                vec![],
            )
            .is_err()
        );
    }
}
