use std::net::{IpAddr, Ipv4Addr};

use crate::SpectraError;

/// SSRF Protection Guard.
///
/// Validates URLs to prevent Server-Side Request Forgery attacks.
/// Checks for private IPs, loopback addresses, link-local, and other
/// reserved ranges that should not be accessed from a server.
pub struct SSRFGuard {
    blocked_networks: Vec<NetworkBlock>,
    allowed_schemes: Vec<String>,
    max_url_length: usize,
}

#[derive(Debug, Clone)]
struct NetworkBlock {
    name: String,
    check: NetworkCheck,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum NetworkCheck {
    PrivateIp,
    Loopback,
    LinkLocal,
    ClassE,
    /// The unspecified address (`0.0.0.0` / `::`). Not loopback by definition,
    /// but connecting to it reaches the local host on every mainstream OS, so
    /// it is blocked for the same reason loopback is.
    Unspecified,
    CustomCidr(String),
    CustomFn(fn(&str) -> bool),
}

impl Default for SSRFGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SSRFGuard {
    pub fn new() -> Self {
        Self {
            blocked_networks: vec![
                NetworkBlock {
                    name: "loopback".into(),
                    check: NetworkCheck::Loopback,
                },
                NetworkBlock {
                    name: "private".into(),
                    check: NetworkCheck::PrivateIp,
                },
                NetworkBlock {
                    name: "link-local".into(),
                    check: NetworkCheck::LinkLocal,
                },
                NetworkBlock {
                    name: "class-e".into(),
                    check: NetworkCheck::ClassE,
                },
                NetworkBlock {
                    name: "unspecified".into(),
                    check: NetworkCheck::Unspecified,
                },
            ],
            allowed_schemes: vec!["http".into(), "https".into()],
            max_url_length: 2048,
        }
    }

    // Creates a guard with relaxed *scheme* and *length* limits, for local
    // development against targets that use other schemes.
    ///
    /// The network blocks are deliberately kept. "Permissive" describes the
    /// URL-shape policy, not authorisation to reach the loopback interface and
    /// cloud metadata services — and since this constructor is easy to reach
    /// for while debugging, silently disabling those blocks would be a
    /// footgun that only shows up in production.
    pub fn permissive() -> Self {
        Self {
            allowed_schemes: vec!["http".into(), "https".into(), "ftp".into()],
            max_url_length: 8192,
            ..Self::new()
        }
    }

    /// Validates a URL and returns the resolved host if valid.
    ///
    /// # Scope and limitations
    ///
    /// This is a *pre-flight* check on the URL as supplied. It cannot detect
    /// DNS rebinding or a public hostname that resolves to a private address,
    /// because resolution happens later, in the HTTP client. Enforcing that
    /// requires resolving the host and pinning the connection to the checked
    /// address — see [`SSRFGuard::validate_resolved_url`], which callers must
    /// use when the connection is actually opened.
    pub fn validate_url(&self, url: &str) -> Result<String, SpectraError> {
        if url.len() > self.max_url_length {
            return Err(SpectraError::Security(format!(
                "URL exceeds maximum length of {}",
                self.max_url_length
            )));
        }

        let parsed = url::Url::parse(url)
            .map_err(|e| SpectraError::Security(format!("Invalid URL: {}", e)))?;

        let scheme = parsed.scheme().to_lowercase();
        if !self.allowed_schemes.contains(&scheme) {
            return Err(SpectraError::Security(format!(
                "Scheme '{}' is not allowed",
                scheme
            )));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| SpectraError::Security("URL has no host".to_string()))?;

        // Hostnames that always denote the local machine or a cloud metadata
        // endpoint. These are never literal IPs, so the `validate_ip` path below
        // cannot see them: without this check `http://localhost/` and
        // `http://metadata.google.internal/` sailed straight through.
        if let Some(blocked) = blocked_hostname(host) {
            return Err(SpectraError::Security(format!(
                "Host '{blocked}' resolves to a local or metadata address and is not allowed"
            )));
        }

        // Any host that is *an* address in some notation must be validated as
        // one. `url::Url` already normalises the dotted, short, decimal, hex and
        // octal IPv4 spellings per the WHATWG URL spec, so `host` is usually
        // canonical by this point; `parse_obfuscated_ip` is the second layer
        // that keeps this correct if a host ever arrives unnormalised (see
        // `check_bypass_attempts`, which inspects the raw string).
        if let Some(ip) = parse_obfuscated_ip(host) {
            self.validate_ip(&ip)?;
        }

        // Check for common SSRF bypass attempts
        self.check_bypass_attempts(url, host)?;

        Ok(host.to_string())
    }

    /// Validate a URL *and* the addresses its host actually resolves to.
    ///
    /// `validate_url` alone is defeatable by pointing a public hostname at an
    /// internal address (`attacker.example` → `169.254.169.254`), which is the
    /// standard SSRF bypass. This resolves the host and checks every returned
    /// address, closing that gap for callers that hold a resolver.
    pub async fn validate_resolved_url(&self, url: &str) -> Result<std::net::IpAddr, SpectraError> {
        let host = self.validate_url(url)?;

        // A literal IP has no resolution step; it is already validated.
        if let Some(ip) = parse_obfuscated_ip(&host) {
            return Ok(ip);
        }

        let port = url::Url::parse(url)
            .ok()
            .and_then(|u| u.port_or_known_default())
            .unwrap_or(80);

        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| SpectraError::Security(format!("cannot resolve host '{host}': {e}")))?
            .collect();

        if addrs.is_empty() {
            return Err(SpectraError::Security(format!(
                "host '{host}' resolved to no addresses"
            )));
        }

        // Every address must pass: a name resolving to both a public and a
        // private address is a rebinding attempt, not a mistake.
        let mut first = None;
        for addr in &addrs {
            self.validate_ip(&addr.ip())?;
            first.get_or_insert(addr.ip());
        }

        Ok(first.expect("non-empty: checked above"))
    }

    /// Validates an IP address against blocked ranges.
    pub fn validate_ip(&self, ip: &IpAddr) -> Result<(), SpectraError> {
        // An IPv4-mapped IPv6 address is checked as the IPv4 address it really
        // is, so `::ffff:127.0.0.1` and `::ffff:7f00:1` are both refused for
        // the same reason `127.0.0.1` is.
        if let Some(v4) = ipv4_mapped(ip) {
            return self.validate_ip(&IpAddr::V4(v4));
        }

        for block in &self.blocked_networks {
            match &block.check {
                NetworkCheck::Loopback => {
                    if is_loopback_ip(ip) {
                        return Err(SpectraError::Security(format!(
                            "IP {} is a loopback address",
                            ip
                        )));
                    }
                }
                NetworkCheck::PrivateIp => {
                    if is_private_ip(ip) {
                        return Err(SpectraError::Security(format!(
                            "IP {} is a private address",
                            ip
                        )));
                    }
                }
                NetworkCheck::LinkLocal => {
                    if is_link_local(ip) {
                        return Err(SpectraError::Security(format!(
                            "IP {} is a link-local address",
                            ip
                        )));
                    }
                }
                NetworkCheck::ClassE => {
                    if is_class_e(ip) {
                        return Err(SpectraError::Security(format!(
                            "IP {} is in Class E range",
                            ip
                        )));
                    }
                }
                NetworkCheck::Unspecified => {
                    if ip.is_unspecified() {
                        return Err(SpectraError::Security(format!(
                            "IP {} is the unspecified address, which routes to the local host",
                            ip
                        )));
                    }
                }
                NetworkCheck::CustomCidr(cidr) => {
                    if let Ok(network) = cidr.parse::<ipnet::IpNet>() {
                        if network.contains(ip) {
                            return Err(SpectraError::Security(format!(
                                "IP {} is in blocked CIDR range {}",
                                ip, cidr
                            )));
                        }
                    }
                }
                NetworkCheck::CustomFn(f) => {
                    if f(&ip.to_string()) {
                        return Err(SpectraError::Security(format!(
                            "IP {} matches custom block rule",
                            ip
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Checks for common SSRF bypass attempts.
    fn check_bypass_attempts(&self, url: &str, host: &str) -> Result<(), SpectraError> {
        // Check for decimal IP encoding
        if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
            if let Ok(ip) = ip_addr_from_str(host) {
                self.validate_ip(&ip)?;
            }
        }

        // Check for IPv6 mapped IPv4
        if let Some(ipv4) = host.strip_prefix("::ffff:") {
            if let Ok(ip) = ipv4.parse::<IpAddr>() {
                self.validate_ip(&ip)?;
            }
        }

        // Check for URL-encoded characters in host
        if host.contains('%') || host.contains("..") {
            return Err(SpectraError::Security(
                "URL contains suspicious characters in host".to_string(),
            ));
        }

        // Check for null bytes
        if url.contains('\0') {
            return Err(SpectraError::Security(
                "URL contains null bytes".to_string(),
            ));
        }

        Ok(())
    }

    /// Adds a custom network block.
    pub fn add_block(&mut self, name: impl Into<String>, check: NetworkCheck) {
        self.blocked_networks.push(NetworkBlock {
            name: name.into(),
            check,
        });
    }

    /// Removes a network block by name.
    pub fn remove_block(&mut self, name: &str) {
        self.blocked_networks.retain(|b| b.name != name);
    }
}

/// Hostnames that always denote the local machine or a cloud metadata service.
///
/// These never appear as literal IPs, so `validate_ip` cannot see them. An
/// allowlist of public hostnames is the wrong tool here: an attacker who
/// controls DNS can point *any* name at an internal address, but these names
/// cannot be pointed outward.
fn blocked_hostname(host: &str) -> Option<&'static str> {
    // Strip a trailing dot, so `localhost.` is caught alongside `localhost`.
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();

    const BLOCKED: &[&str] = &[
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        // Cloud instance metadata. Reading these from a scan target leaks the
        // credentials of the machine running the scan.
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        // Container and service-discovery names that resolve inward.
        "host.docker.internal",
        "gateway.docker.internal",
        "kubernetes.default",
        "kubernetes.default.svc",
    ];

    BLOCKED.iter().copied().find(|name| normalized == *name)
}

/// Parse a host that denotes an IP address, including obfuscated notations.
///
/// `IpAddr::from_str` accepts only the canonical dotted-quad and IPv6 forms, so
/// these all reach an HTTP client as `127.0.0.1` while failing to parse here:
/// `127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`. Anything that looks like
/// an address in one of those notations is normalised and returned, so
/// `validate_ip` gets a real `IpAddr` to check.
fn parse_obfuscated_ip(host: &str) -> Option<IpAddr> {
    // Strip an IPv6 zone identifier and surrounding brackets first.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next().unwrap_or(host);

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }

    // `::ffff:127.0.0.1` and friends: peel the prefix and re-check the tail.
    if let Some(tail) = host.strip_prefix("::ffff:") {
        if let Some(ip) = parse_obfuscated_ip(tail) {
            return Some(ip);
        }
    }

    // A bare integer is an IPv4 address: 2130706433 == 127.0.0.1. Decimal,
    // hexadecimal and octal spellings are all accepted by HTTP clients, so all
    // three are normalised here.
    if let Some(value) = parse_ip_integer(host) {
        return Some(IpAddr::from(Ipv4Addr::from(value)));
    }

    // Dotted parts, each of which may be decimal, hex (0x..) or octal (0..).
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 && parts.len() <= 4 {
            let mut octets = [0u8; 4];
            for (idx, part) in parts.iter().enumerate() {
                let value = parse_ip_octet(part)?;
                octets[idx] = value;
            }
            // Shorthand forms zero-fill the remaining octets, following
            // `inet_aton`: `127.1` is 127.1.0.0. Whichever way the trailing
            // octets are filled, the result stays inside the blocked range,
            // which is what matters for the check.
            return Some(IpAddr::from(octets));
        }
    }

    None
}

/// If `ip` is an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), return the
/// embedded IPv4 address.
///
/// `::ffff:127.0.0.1` and `::ffff:7f00:1` are the same address written two ways,
/// and a socket connecting to either reaches 127.0.0.1. Checking only the
/// dotted form let the hexadecimal form through.
fn ipv4_mapped(ip: &IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    let segments = v6.segments();
    // ::ffff:a.b.c.d  =>  0,0,0,0,0,0xffff,a,b  (a and b are the two halves)
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let hi = segments[6].to_be_bytes();
        let lo = segments[7].to_be_bytes();
        return Some(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]));
    }
    None
}

/// Parse a bare integer host in decimal, hexadecimal or octal notation.
///
/// `2130706433`, `0x7f000001` and `017700000001` are all 127.0.0.1.
fn parse_ip_integer(host: &str) -> Option<u32> {
    if host.is_empty() {
        return None;
    }
    if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if host.chars().all(|c| c.is_ascii_digit()) {
        return host.parse::<u32>().ok();
    }
    // A leading zero with more digits means octal, as in C.
    if host.len() > 1
        && host.starts_with('0')
        && host[1..].chars().all(|c| ('0'..='7').contains(&c))
    {
        return u32::from_str_radix(&host[1..], 8).ok();
    }
    None
}

/// Parse a single IPv4 octet written in decimal, hex, or octal.
fn parse_ip_octet(part: &str) -> Option<u8> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).ok();
    }
    // A leading zero means octal, as in C and in what browsers accept. A bare
    // "0" is just zero.
    if part.len() > 1 && part.starts_with('0') {
        return u8::from_str_radix(&part[1..], 8).ok();
    }
    part.parse::<u8>().ok()
}

fn ip_addr_from_str(s: &str) -> Result<IpAddr, ()> {
    s.parse().map_err(|_| ())
}

fn is_loopback_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.octets()[0] == 127,
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let o = ipv4.octets();
            o[0] == 10 || (o[0] == 172 && o[1] >= 16 && o[1] <= 31) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] & 0xfe00 == 0xfc00
        }
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] & 0xffc0 == 0xfe80
        }
    }
}

fn is_class_e(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] >= 240
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_blocks_loopback() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_ip(&"127.0.0.1".parse().unwrap()).is_err());
        assert!(guard.validate_ip(&"::1".parse().unwrap()).is_err());
    }

    #[test]
    fn guard_blocks_private() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_ip(&"10.0.0.1".parse().unwrap()).is_err());
        assert!(guard.validate_ip(&"192.168.1.1".parse().unwrap()).is_err());
        assert!(guard.validate_ip(&"172.16.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn guard_allows_public() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_ip(&"8.8.8.8".parse().unwrap()).is_ok());
        assert!(guard.validate_ip(&"1.1.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn guard_blocks_link_local() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_ip(&"169.254.1.1".parse().unwrap()).is_err());
    }

    #[test]
    fn guard_blocks_class_e() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_ip(&"240.0.0.1".parse().unwrap()).is_err());
        assert!(guard
            .validate_ip(&"255.255.255.255".parse().unwrap())
            .is_err());
    }

    #[test]
    fn guard_blocks_bad_schemes() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_url("ftp://example.com").is_err());
        assert!(guard.validate_url("file:///etc/passwd").is_err());
        assert!(guard.validate_url("gopher://example.com").is_err());
    }

    #[test]
    fn guard_allows_good_urls() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_url("https://example.com").is_ok());
        assert!(guard.validate_url("http://example.com/path").is_ok());
    }

    #[test]
    fn guard_blocks_oversized_urls() {
        let guard = SSRFGuard::new();
        let long_url = format!("https://example.com/{}", "a".repeat(3000));
        assert!(guard.validate_url(&long_url).is_err());
    }

    #[test]
    fn guard_blocks_suspicious_chars() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_url("https://exam%le.com").is_err());
        assert!(guard.validate_url("https://exam..ple.com").is_err());
    }

    #[test]
    fn guard_blocks_null_bytes() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_url("https://example.com\0evil.com").is_err());
    }

    #[test]
    fn permissive_guard_allows_more() {
        let guard = SSRFGuard::permissive();
        assert!(guard.validate_url("ftp://example.com").is_ok());
    }

    #[test]
    fn add_remove_blocks() {
        let mut guard = SSRFGuard::new();
        guard.add_block("test", NetworkCheck::Loopback);
        guard.remove_block("test");
        // After removing, loopback is still blocked by default
        assert!(guard.validate_ip(&"127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn ipv6_loopback_blocked() {
        let guard = SSRFGuard::new();
        assert!(guard.validate_ip(&"::1".parse().unwrap()).is_err());
    }

    #[test]
    fn ipv6_unique_local_blocked() {
        let guard = SSRFGuard::new();
        // fc00::/7 is unique local address (private)
        assert!(guard.validate_ip(&"fc00::1".parse().unwrap()).is_err());
        assert!(guard.validate_ip(&"fd00::1".parse().unwrap()).is_err());
    }
}

#[cfg(test)]
mod bypass_tests {
    //! One test per bypass that previously passed `validate_url`.
    //!
    //! These are the cases that made the guard decorative: the URL as written
    //! looked public, but the HTTP client would have connected to the local
    //! machine or to a cloud metadata endpoint.

    use super::*;

    fn guard() -> SSRFGuard {
        SSRFGuard::new()
    }

    // --- Hostnames that are never literal IPs -------------------------------

    #[test]
    fn blocks_localhost() {
        assert!(guard().validate_url("http://localhost/").is_err());
        assert!(guard().validate_url("http://localhost:8080/admin").is_err());
        assert!(guard().validate_url("https://localhost/").is_err());
    }

    #[test]
    fn blocks_localhost_with_trailing_dot() {
        // `localhost.` is the same host and used to slip past a bare comparison.
        assert!(guard().validate_url("http://localhost./").is_err());
    }

    #[test]
    fn blocks_localhost_case_insensitively() {
        assert!(guard().validate_url("http://LOCALHOST/").is_err());
        assert!(guard().validate_url("http://LocalHost/").is_err());
    }

    #[test]
    fn blocks_cloud_metadata_endpoints() {
        // The highest-value target: these hand out the credentials of the
        // machine running the scan.
        for url in [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata/",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            assert!(guard().validate_url(url).is_err(), "{url} must be blocked");
        }
    }

    #[test]
    fn blocks_container_and_kubernetes_service_names() {
        for url in [
            "http://host.docker.internal/",
            "http://gateway.docker.internal/",
            "http://kubernetes.default.svc/",
        ] {
            assert!(guard().validate_url(url).is_err(), "{url} must be blocked");
        }
    }

    #[test]
    fn does_not_block_lookalike_hostnames() {
        // A naive substring check would block these, and an over-broad block
        // list is its own denial of service against legitimate targets.
        for url in [
            "https://localhosting.example.com/",
            "https://mymetadata.example.com/",
            "https://notlocalhost.example.com/",
        ] {
            assert!(
                guard().validate_url(url).is_ok(),
                "{url} is a public host and must be allowed"
            );
        }
    }

    // --- Obfuscated IP literals ---------------------------------------------
    //
    // Note on provenance: `url::Url` already normalises the dotted, short,
    // decimal, hex and octal IPv4 spellings (WHATWG URL spec), so most of these
    // were caught by `validate_ip` on the canonical form even before
    // `parse_obfuscated_ip` existed. These tests pin the end-to-end property
    // (the URL is refused) and the parser's own contract separately, so neither
    // can regress silently if the URL parser's behaviour changes.

    #[test]
    fn blocks_short_form_loopback() {
        for url in ["http://127.1/", "http://127.0.1/", "http://127.1.1/"] {
            assert!(guard().validate_url(url).is_err(), "{url} must be blocked");
        }
    }

    #[test]
    fn blocks_decimal_encoded_loopback() {
        // 2130706433 == 0x7F000001 == 127.0.0.1
        assert!(guard().validate_url("http://2130706433/").is_err());
    }

    #[test]
    fn blocks_hex_encoded_loopback() {
        assert!(guard().validate_url("http://0x7f000001/").is_err());
        assert!(guard().validate_url("http://0x7f.0.0.1/").is_err());
    }

    #[test]
    fn blocks_octal_encoded_loopback() {
        // 0177 == 127 in octal.
        assert!(guard().validate_url("http://0177.0.0.1/").is_err());
        assert!(guard().validate_url("http://017700000001/").is_err());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_loopback() {
        // `::ffff:7f00:1` is the hexadecimal spelling of `::ffff:127.0.0.1`.
        // Checking only the dotted form let the hex form through.
        for url in [
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:7f00:1]/",
            "http://[::ffff:a00:1]/", // 10.0.0.1
        ] {
            assert!(guard().validate_url(url).is_err(), "{url} must be blocked");
        }
    }

    #[test]
    fn ipv4_mapped_extraction_matches_dotted_form() {
        let from_dotted = ipv4_mapped(&"::ffff:127.0.0.1".parse().unwrap());
        let from_hex = ipv4_mapped(&"::ffff:7f00:1".parse().unwrap());
        assert_eq!(from_dotted, Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(
            from_dotted, from_hex,
            "both spellings must extract the same IPv4 address"
        );
    }

    #[test]
    fn ipv4_mapped_ignores_genuine_ipv6() {
        assert_eq!(ipv4_mapped(&"2001:db8::1".parse().unwrap()), None);
        assert_eq!(ipv4_mapped(&"127.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn does_not_block_public_ipv4_mapped_ipv6() {
        // ::ffff:8.8.8.8 is a public address and must stay reachable.
        assert!(guard().validate_url("http://[::ffff:8.8.8.8]/").is_ok());
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(guard().validate_url("http://[::1]/").is_err());
    }

    #[test]
    fn blocks_obfuscated_private_ranges() {
        for url in [
            "http://0x0a.0.0.1/",    // 10.0.0.1
            "http://10.1/",          // 10.1.0.0
            "http://0300.0250.0.1/", // 192.168.0.1, octal
        ] {
            assert!(guard().validate_url(url).is_err(), "{url} must be blocked");
        }
    }

    #[test]
    fn blocks_unspecified_address() {
        // 0.0.0.0 reaches the local host on every mainstream OS.
        assert!(guard().validate_url("http://0.0.0.0/").is_err());
        assert!(guard().validate_url("http://[::]/").is_err());
    }

    #[test]
    fn still_allows_public_addresses_in_odd_notation() {
        // The obfuscation parser must not become a blanket deny.
        assert!(guard().validate_url("http://8.8.8.8/").is_ok());
        assert!(guard().validate_url("http://1.1.1.1:443/").is_ok());
        assert!(guard().validate_url("https://93.184.216.34/").is_ok());
    }

    // --- Unit tests for the parser itself -----------------------------------

    #[test]
    fn integer_parser_handles_each_radix() {
        // 0x7F000001 == 2130706433, and 127.0.0.1 == 0x7F000001, so the
        // integer form of 127.0.0.1 is 2130706433.
        let expect = Some(2_130_706_433u32);
        for host in ["2130706433", "0x7f000001", "0X7F000001"] {
            assert_eq!(parse_ip_integer(host), expect, "host `{host}`");
        }
        // Not addresses, so not parsed as addresses. Note that a long octal
        // form such as `017700000001` overflows u32 and is correctly rejected —
        // it is not a representable IPv4 address in any encoding.
        for host in ["", "0x", "example", "0x1g", "017700000001"] {
            assert_eq!(parse_ip_integer(host), None, "host `{host}`");
        }
    }

    #[test]
    fn obfuscated_parser_normalises_short_forms() {
        // `inet_aton` zero-fills: `127.1` is 127.1.0.0, `127.0.1` is 127.0.0.1.
        // Every form below lands inside 127.0.0.0/8, which is the property the
        // security check depends on.
        for (host, expected) in [
            ("127.0.0.1", "127.0.0.1"),
            ("127.0.1", "127.0.1.0"),
            ("127.1", "127.1.0.0"),
            ("127.1.1", "127.1.1.0"),
            ("2130706433", "127.0.0.1"),
            ("0x7f000001", "127.0.0.1"),
            ("0177.0.0.1", "127.0.0.1"),
            ("0x7f.0.0.1", "127.0.0.1"),
        ] {
            assert_eq!(
                parse_obfuscated_ip(host),
                Some(expected.parse::<IpAddr>().unwrap()),
                "host `{host}` should normalise to {expected}"
            );
        }
    }

    #[test]
    fn every_short_form_of_loopback_is_rejected() {
        // The property that actually matters, independent of fill semantics.
        for host in ["127.0.0.1", "127.0.1", "127.1", "127.1.1"] {
            let ip = parse_obfuscated_ip(host).expect("must parse as an address");
            assert!(
                SSRFGuard::new().validate_ip(&ip).is_err(),
                "{host} ({ip}) must be treated as loopback"
            );
        }
    }

    #[test]
    fn obfuscated_parser_returns_none_for_real_hostnames() {
        for host in ["example.com", "localhost", "not-an-ip", ""] {
            assert_eq!(parse_obfuscated_ip(host), None, "host `{host}`");
        }
    }

    #[test]
    fn obfuscated_parser_does_not_panic_on_hostile_input() {
        for host in [
            "...",
            "999.999.999.999",
            "1.2.3.4.5",
            "0x",
            "0x.",
            "0xffffffffffffffffffffffffffff",
            &"1.".repeat(4096),
        ] {
            let _ = parse_obfuscated_ip(host);
        }
    }

    #[test]
    fn octet_parser_handles_each_notation() {
        assert_eq!(parse_ip_octet("127"), Some(127));
        assert_eq!(parse_ip_octet("0x7f"), Some(127));
        assert_eq!(parse_ip_octet("0177"), Some(127));
        assert_eq!(parse_ip_octet("0"), Some(0));
        assert_eq!(parse_ip_octet("256"), None);
        assert_eq!(parse_ip_octet(""), None);
    }

    // --- Scheme handling ----------------------------------------------------

    #[test]
    fn blocks_non_http_schemes() {
        for url in [
            "file:///etc/passwd",
            "gopher://127.0.0.1/",
            "ftp://example.com/",
        ] {
            assert!(guard().validate_url(url).is_err(), "{url} must be blocked");
        }
    }

    #[test]
    fn permissive_guard_still_blocks_loopback() {
        // `permissive()` is documented as "development/testing", not as
        // "disable all protection". It relaxes scheme and length limits; it
        // must not re-open loopback.
        assert!(SSRFGuard::permissive()
            .validate_url("http://127.0.0.1/")
            .is_err());
    }

    #[tokio::test]
    async fn resolved_validation_rejects_a_name_pointing_at_loopback() {
        // The DNS-rebinding case: a public-looking name whose address is
        // internal. `localhost` stands in for it so the test needs no network.
        let err = guard()
            .validate_resolved_url("http://localhost/")
            .await
            .expect_err("must be refused");
        assert!(matches!(err, SpectraError::Security(_)));
    }

    #[tokio::test]
    async fn resolved_validation_accepts_a_literal_public_address() {
        // No DNS lookup happens for a literal address, so this is hermetic.
        let ip = guard()
            .validate_resolved_url("http://8.8.8.8/")
            .await
            .expect("public literal must be accepted");
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().unwrap());
    }
}
