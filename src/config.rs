//! Converts a bounded TOML file into listener settings and validated routing.
//!
//! This is the only TOML boundary. Runtime modules receive domain values rather
//! than configuration tables, and startup fails if any route is invalid.

use crate::routing::{Route, RouteError, RoutingTable, UpstreamAddress, UpstreamGroup};
use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read},
    net::{AddrParseError, IpAddr, SocketAddr},
    path::Path,
};
use toml::de::DeTable as Table;

pub(crate) const DEFAULT_CONFIG: &str = "/etc/sederial/sederial.toml";
const DEFAULT_DNS_PORT: u16 = 53;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ROUTES: usize = 4096;

/// Startup settings produced by whole-file validation before listeners bind.
#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) listen: SocketAddr,
    pub(crate) routing: RoutingTable,
}
impl Config {
    /// Reads at most one byte beyond the configuration size limit and validates it.
    ///
    /// # Errors
    /// Returns file/UTF-8 errors, TOML syntax errors, or invalid settings such as
    /// unknown keys, invalid endpoints, forwarding loops and duplicate routes.
    pub(crate) fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut text = String::new();
        // The extra byte distinguishes an exactly-full file from an oversized
        // file without reading an unbounded input or trusting file metadata.
        File::open(path)
            .map_err(ConfigError::Io)?
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(ConfigError::Io)?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid("configuration exceeds 1 MiB".into()));
        }
        Self::parse(&text)
    }
    /// Validates the complete configuration; no partially valid table escapes.
    fn parse(text: &str) -> Result<Self, ConfigError> {
        let table = Table::parse(text)
            .map_err(ConfigError::Syntax)?
            .into_inner();
        reject_unknown_keys(&table, &["listen", "default", "route"], "configuration")?;
        let listen = parse_address(required_string(&table, "listen")?).map_err(|_| {
            ConfigError::Invalid(
                "listen must be an IP address with an optional port (IPv6 with port: [address]:port)"
                    .into(),
            )
        })?;
        // Listeners share the concrete unicast/nonzero-port restriction with
        // upstreams, including IPv4-mapped normalization. Wildcard binding would
        // require destination-address tracking to send UDP replies from the
        // address the client originally queried.
        let listen = UpstreamAddress::new(listen)
            .map_err(|error| ConfigError::Invalid(format!("listen: {error}")))?
            .socket();
        let default_table = table
            .get("default")
            .and_then(|v| v.get_ref().as_table())
            .ok_or_else(|| ConfigError::Invalid("missing [default] table".into()))?;
        reject_unknown_keys(default_table, &["servers"], "default")?;
        let default = parse_upstream_group(default_table, listen)?;
        let mut routes = Vec::new();
        if let Some(value) = table.get("route") {
            let array = value
                .get_ref()
                .as_array()
                .ok_or_else(|| ConfigError::Invalid("route must be an array of tables".into()))?;
            if array.len() > MAX_ROUTES {
                return Err(ConfigError::Invalid(format!(
                    "at most {MAX_ROUTES} routes are supported"
                )));
            }
            for (route_index, value) in array.iter().enumerate() {
                let route_table = value.get_ref().as_table().ok_or_else(|| {
                    ConfigError::Invalid(format!("route {route_index}: expected a table"))
                })?;
                reject_unknown_keys(
                    route_table,
                    &["domain", "servers"],
                    &format!("route {route_index}"),
                )?;
                let suffix = required_string(route_table, "domain")?
                    .parse()
                    .map_err(|error| {
                        ConfigError::Invalid(format!("route {route_index} domain: {error}"))
                    })?;
                routes.push(Route {
                    suffix,
                    upstreams: parse_upstream_group(route_table, listen)?,
                });
            }
        }
        Ok(Self {
            listen,
            routing: RoutingTable::new(default, routes).map_err(ConfigError::Routing)?,
        })
    }
}

/// Parses a literal IP endpoint, defaulting a missing port to DNS port 53.
///
/// Bare IPv6 is always an address; an explicit IPv6 port requires brackets.
/// Hostnames are rejected, so loading configuration never needs DNS resolution.
fn parse_address(raw: &str) -> Result<SocketAddr, AddrParseError> {
    raw.parse().or_else(|_| {
        let ip = match raw.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            Some(ip) => IpAddr::V6(ip.parse()?),
            None => raw.parse()?,
        };
        Ok(SocketAddr::new(ip, DEFAULT_DNS_PORT))
    })
}

fn required_string<'a>(table: &'a Table<'_>, key: &str) -> Result<&'a str, ConfigError> {
    table
        .get(key)
        .and_then(|v| v.get_ref().as_str())
        .ok_or_else(|| ConfigError::Invalid(format!("{key}: expected a string")))
}
fn reject_unknown_keys(
    table: &Table<'_>,
    allowed: &[&str],
    context: &str,
) -> Result<(), ConfigError> {
    for key in table.keys() {
        if !allowed.contains(&key.get_ref().as_ref()) {
            return Err(ConfigError::Invalid(format!(
                "{context}: unknown key {key:?}"
            )));
        }
    }
    Ok(())
}
/// Preserves configured failover order while validating endpoints and self-loops.
fn parse_upstream_group(
    table: &Table<'_>,
    listen: SocketAddr,
) -> Result<UpstreamGroup, ConfigError> {
    let values = table
        .get("servers")
        .and_then(|v| v.get_ref().as_array())
        .ok_or_else(|| {
            ConfigError::Invalid(
                "servers: expected an array of IP address strings with optional ports".into(),
            )
        })?;
    let mut addresses = Vec::new();
    for value in values {
        let raw = value
            .get_ref()
            .as_str()
            .ok_or_else(|| ConfigError::Invalid("server address must be a string".into()))?;
        let address = parse_address(raw)
            .map_err(|_| ConfigError::Invalid(format!("invalid upstream address {raw:?}")))?;
        // Compare canonical IPs so an IPv4-mapped spelling cannot hide a direct
        // loop. Loops through other resolvers are outside local validation.
        if address.port() == listen.port()
            && address.ip().to_canonical() == listen.ip().to_canonical()
        {
            return Err(ConfigError::ForwardingLoop);
        }
        addresses.push(UpstreamAddress::new(address).map_err(ConfigError::Routing)?);
    }
    UpstreamGroup::new(addresses).map_err(ConfigError::Routing)
}

/// Distinguishes file access, TOML syntax and domain validation failures.
#[derive(Debug)]
pub(crate) enum ConfigError {
    Io(io::Error),
    Syntax(toml::de::Error),
    Invalid(String),
    ForwardingLoop,
    Routing(RouteError),
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Syntax(e) => e.fmt(f),
            Self::Invalid(e) => f.write_str(e),
            Self::ForwardingLoop => {
                f.write_str("upstream points to the listener (forwarding loop)")
            }
            Self::Routing(e) => e.fmt(f),
        }
    }
}
impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Syntax(e) => Some(e),
            Self::Routing(e) => Some(e),
            Self::Invalid(_) | Self::ForwardingLoop => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const VALID: &str = "listen='127.0.0.1:5300'\n[default]\nservers=['1.1.1.1:53']\n";
    #[test]
    fn parses_complete_toml_and_ipv6() {
        let config = Config::parse("listen = '[::1]:5300'\n[default]\nservers = [\n '[::1]:5353', # comment\n]\n[[route]]\ndomain = '_tcp.EXAMPLE.test.'\nservers = ['127.0.0.1:5354']").unwrap();
        assert!(config.listen.is_ipv6());
        assert_eq!(config.routing.routes().len(), 1);
    }
    #[test]
    fn defaults_omitted_ports_and_preserves_explicit_ports() {
        for (raw, expected) in [
            ("127.0.0.1", "127.0.0.1:53"),
            ("127.0.0.1:53", "127.0.0.1:53"),
            ("127.0.0.1:5353", "127.0.0.1:5353"),
            ("::1", "[::1]:53"),
            ("[::1]", "[::1]:53"),
            ("[::1]:53", "[::1]:53"),
            ("[::1]:5353", "[::1]:5353"),
            // Without brackets, the final segment belongs to the IPv6 address.
            ("2001:db8::1:5353", "[2001:db8::1:5353]:53"),
        ] {
            let expected: SocketAddr = expected.parse().unwrap();
            let config = Config::parse(&format!(
                "listen='{raw}'\n[default]\nservers=['192.0.2.53']"
            ))
            .unwrap();
            assert_eq!(config.listen, expected, "listen={raw}");
            let config = Config::parse(&format!(
                "listen='127.0.0.2:5300'\n[default]\nservers=['{raw}']\n\
                 [[route]]\ndomain='example.test'\nservers=['{raw}']"
            ))
            .unwrap();
            assert_eq!(config.routing.default().servers()[0].socket(), expected);
            assert_eq!(
                config.routing.routes()[0].upstreams.servers()[0].socket(),
                expected
            );
        }
    }
    #[test]
    fn default_ports_preserve_loop_and_duplicate_detection() {
        for (listen, upstream) in [
            ("127.0.0.1", "127.0.0.1:53"),
            ("127.0.0.1:53", "127.0.0.1"),
            ("::1", "[::1]:53"),
            ("[::1]:53", "[::1]"),
            ("127.0.0.1", "::ffff:127.0.0.1"),
        ] {
            for group in [
                format!("[default]\nservers=['{upstream}']"),
                format!(
                    "[default]\nservers=['192.0.2.53']\n\
                     [[route]]\ndomain='example.test'\nservers=['{upstream}']"
                ),
            ] {
                let error = Config::parse(&format!("listen='{listen}'\n{group}")).unwrap_err();
                assert!(matches!(error, ConfigError::ForwardingLoop));
            }
        }
        for servers in [
            "['1.1.1.1', '1.1.1.1:53']",
            "['::1', '[::1]:53']",
            "['[::1]', '::1']",
            "['192.0.2.53', '[::ffff:192.0.2.53]:53']",
            "['::ffff:192.0.2.53', '192.0.2.53:53']",
        ] {
            let error = Config::parse(&format!(
                "listen='127.0.0.1:5300'\n[default]\nservers={servers}"
            ))
            .unwrap_err();
            assert!(matches!(
                error,
                ConfigError::Routing(RouteError::DuplicateServer)
            ));
        }
    }
    #[test]
    fn listen_keeps_the_canonical_unicast_address() {
        let config =
            Config::parse("listen='[::ffff:127.0.0.1]'\n[default]\nservers=['192.0.2.53']\n")
                .unwrap();
        assert_eq!(config.listen, "127.0.0.1:53".parse::<SocketAddr>().unwrap());
    }
    #[test]
    fn rejects_invalid_config_as_a_whole() {
        for input in [
            "",
            "listen='localhost:53'",
            "listen='0.0.0.0:53'\n[default]\nservers=['1.1.1.1:53']",
            "listen='127.0.0.1:0'\n[default]\nservers=['1.1.1.1:53']",
            "listen=42",
        ] {
            assert!(Config::parse(input).is_err(), "{input}");
        }
        for servers in [
            "[]",
            "['0.0.0.0:53']",
            "['0.0.0.0']",
            "['::']",
            "['1.1.1.1:0']",
            "['1.1.1.1:']",
            "['1.1.1.1:65536']",
            "['1.1.1.1:dns']",
            "['[::1]:0']",
            "['[::1]:']",
            "['[::1]:65536']",
            "['[::1]:dns']",
            "['[1.1.1.1]']",
            "[':53']",
            "['localhost']",
            "['224.0.0.1:53']",
            "['255.255.255.255:53']",
            "['127.0.0.1:5300']",
            "['1.1.1.1:53','1.1.1.1:53']",
            "['bad']",
            "[1]",
        ] {
            assert!(
                Config::parse(&format!(
                    "listen='127.0.0.1:5300'\n[default]\nservers={servers}"
                ))
                .is_err()
            );
        }
        for extra in [
            "unknown=true",
            "[[route]]\ndomain='bad..test'\nservers=['1.1.1.1:53']",
            "[[route]]\ndomain='test'",
            "[[route]]\ndomain='test'\nservers=[]",
            "[[route]]\ndomain='*.test'\nservers=['1.1.1.1:53']",
            "[[route]]\ndomain='test'\nservers=['1.1.1.1:53']\n[[route]]\ndomain='TEST.'\nservers=['1.0.0.1:53']",
        ] {
            assert!(
                Config::parse(&format!("{VALID}{extra}")).is_err(),
                "{extra}"
            );
        }
    }
}
