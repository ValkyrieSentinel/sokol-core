//! Addresses the node must never drop, whoever asks: an automatic block of the node itself,
//! its gateway, its mesh peers or the operator's network would cut the node off.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Reason given for this host's own interface addresses.
pub const LOCAL_ADDRESS: &str = "address of this node";

pub const PREFIX_TOO_WIDE: &str = "prefix wider than --min-block-prefix-v4/-v6 allows";

#[derive(Clone)]
pub struct BlockPolicy {
    protected: Vec<(IpNet, &'static str)>,
    /// Shortest prefix a block may have: a detector mistake must not cut off half the internet.
    min_prefix_v4: u8,
    min_prefix_v6: u8,
}

impl BlockPolicy {
    /// Loopback, unspecified, broadcast, multicast and IPv6 link-local (NDP with the router).
    pub fn builtin() -> Self {
        let builtin = [
            ("127.0.0.0/8", "loopback"),
            ("::1/128", "loopback"),
            ("0.0.0.0/32", "unspecified address"),
            ("::/128", "unspecified address"),
            ("255.255.255.255/32", "broadcast"),
            ("224.0.0.0/4", "multicast"),
            ("ff00::/8", "multicast"),
            ("fe80::/10", "IPv6 link-local"),
        ];
        Self {
            protected: builtin
                .iter()
                // Every entry parses (test `builtin_ranges_all_parse`).
                .filter_map(|(net, why)| net.parse().ok().map(|net| (net, *why)))
                .collect(),
            min_prefix_v4: 16,
            min_prefix_v6: 48,
        }
    }

    pub fn set_min_prefix(&mut self, v4: u8, v6: u8) {
        self.min_prefix_v4 = v4.min(32);
        self.min_prefix_v6 = v6.min(128);
    }

    /// Checks a block target. A prefix is refused if it is wider than the minimum, or if it
    /// contains, or lies inside, any protected address or range.
    pub fn check_net(&self, net: IpNet) -> Result<(), &'static str> {
        if net.prefix_len() == net.max_prefix_len() {
            return self.check(net.addr());
        }
        let min = match net {
            IpNet::V4(_) => self.min_prefix_v4,
            IpNet::V6(_) => self.min_prefix_v6,
        };
        if net.prefix_len() < min {
            return Err(PREFIX_TOO_WIDE);
        }
        // Two prefixes overlap exactly when one contains the other's network address.
        match self
            .protected
            .iter()
            .find(|(p, _)| net.contains(&p.network()) || p.contains(&net.network()))
        {
            Some((_, why)) => Err(why),
            None => Ok(()),
        }
    }

    pub fn protect(&mut self, net: IpNet, why: &'static str) {
        self.protected.push((net, why));
    }

    pub fn protect_ip(&mut self, ip: IpAddr, why: &'static str) {
        self.protect(IpNet::from(canonical(ip)), why);
    }

    /// `Err` names why the address is protected.
    pub fn check(&self, ip: IpAddr) -> Result<(), &'static str> {
        let ip = canonical(ip);
        match self.protected.iter().find(|(net, _)| net.contains(&ip)) {
            Some((_, why)) => Err(why),
            None => Ok(()),
        }
    }

    /// This policy plus the host's own addresses and default gateways.
    pub fn with_host(&self, host: &HostView) -> Self {
        let mut policy = self.clone();
        for ip in &host.addresses {
            policy.protect_ip(*ip, LOCAL_ADDRESS);
        }
        for ip in &host.gateways {
            policy.protect_ip(*ip, "default gateway");
        }
        policy
    }
}

/// The host facts the policy protects, as read now. Compared between reads to notice a change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostView {
    pub addresses: std::collections::BTreeSet<IpAddr>,
    pub gateways: std::collections::BTreeSet<IpAddr>,
}

impl HostView {
    /// Reads the interface addresses and default gateways. An error (not an empty result) when
    /// they cannot be read, so a failed read never looks like "nothing to protect".
    pub fn discover() -> Result<Self, String> {
        Ok(Self {
            addresses: local_interface_addresses()?
                .into_iter()
                .map(canonical)
                .collect(),
            gateways: default_gateways()?.into_iter().map(canonical).collect(),
        })
    }

    /// What `self` protects that `before` did not, and the reverse.
    pub fn diff(&self, before: &HostView) -> (Vec<IpAddr>, Vec<IpAddr>) {
        let now: std::collections::BTreeSet<&IpAddr> =
            self.addresses.iter().chain(&self.gateways).collect();
        let was: std::collections::BTreeSet<&IpAddr> =
            before.addresses.iter().chain(&before.gateways).collect();
        (
            now.difference(&was).map(|ip| **ip).collect(),
            was.difference(&now).map(|ip| **ip).collect(),
        )
    }
}

/// The policy in force, replaced as a whole when the host changes; readers take a snapshot.
#[derive(Clone)]
pub struct PolicyHandle(std::sync::Arc<std::sync::RwLock<std::sync::Arc<BlockPolicy>>>);

impl PolicyHandle {
    pub fn new(policy: BlockPolicy) -> Self {
        Self(std::sync::Arc::new(std::sync::RwLock::new(
            std::sync::Arc::new(policy),
        )))
    }

    pub fn current(&self) -> std::sync::Arc<BlockPolicy> {
        self.0.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn replace(&self, policy: BlockPolicy) {
        *self.0.write().unwrap_or_else(|p| p.into_inner()) = std::sync::Arc::new(policy);
    }
}

/// `::ffff:a.b.c.d` is the same host as `a.b.c.d`.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn local_interface_addresses() -> Result<Vec<IpAddr>, String> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list that we walk read-only and release with freeifaddrs.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return Err(format!(
                "getifaddrs failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut cur = head;
        while !cur.is_null() {
            let addr = (*cur).ifa_addr;
            if !addr.is_null() {
                match (*addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(addr as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            sin.sin_addr.s_addr,
                        ))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(addr as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    Ok(out)
}

fn default_gateways() -> Result<Vec<IpAddr>, String> {
    let read = |path: &str| {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))
    };
    let mut out = parse_ipv4_default_gateways(&read("/proc/net/route")?);
    // A host without IPv6 has no ipv6_route: that is not a failure.
    match std::fs::read_to_string("/proc/net/ipv6_route") {
        Ok(table) => out.extend(parse_ipv6_default_gateways(&table)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot read /proc/net/ipv6_route: {}", e)),
    }
    Ok(out)
}

/// `/proc/net/route`: Iface Destination Gateway ... in little-endian hex.
fn parse_ipv4_default_gateways(table: &str) -> Vec<IpAddr> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let (_iface, destination, gateway) = (cols.next()?, cols.next()?, cols.next()?);
            if destination != "00000000" {
                return None;
            }
            let gw = u32::from_str_radix(gateway, 16).ok()?;
            (gw != 0).then(|| IpAddr::V4(Ipv4Addr::from(u32::from_be(gw))))
        })
        .collect()
}

/// `/proc/net/ipv6_route`: dest dest_len src src_len next_hop ... in big-endian hex.
fn parse_ipv6_default_gateways(table: &str) -> Vec<IpAddr> {
    table
        .lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let destination = cols.next()?;
            let prefix_len = cols.next()?;
            let next_hop = cols.nth(2)?;
            if prefix_len != "00" || destination.chars().any(|c| c != '0') {
                return None;
            }
            let hop = u128::from_str_radix(next_hop, 16).ok()?;
            (hop != 0).then(|| IpAddr::V6(Ipv6Addr::from(hop)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_host_view_protects_its_addresses_and_reports_changes() {
        let base = BlockPolicy::builtin();
        let mut view = HostView::default();
        view.addresses.insert(ip("10.0.0.5"));
        view.gateways.insert(ip("10.0.0.1"));
        let policy = base.with_host(&view);
        assert_eq!(policy.check(ip("10.0.0.5")), Err(LOCAL_ADDRESS));
        assert_eq!(policy.check(ip("10.0.0.1")), Err("default gateway"));
        assert!(
            base.check(ip("10.0.0.5")).is_ok(),
            "the base policy is not changed"
        );
        let mut moved = view.clone();
        moved.addresses.remove(&ip("10.0.0.5"));
        moved.addresses.insert(ip("::ffff:10.0.0.6"));
        let moved = HostView {
            addresses: moved.addresses.into_iter().map(canonical).collect(),
            ..moved
        };
        assert_eq!(
            moved.diff(&view),
            (vec![ip("10.0.0.6")], vec![ip("10.0.0.5")])
        );
        assert!(
            HostView::discover().is_ok(),
            "this host's addresses can be read"
        );
    }

    #[test]
    fn builtin_ranges_all_parse() {
        // builtin() skips an entry that does not parse; none may.
        assert_eq!(BlockPolicy::builtin().protected.len(), 8);
    }

    #[test]
    fn builtin_ranges_are_protected() {
        let policy = BlockPolicy::builtin();
        for protected in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "224.0.0.251",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                policy.check(ip(protected)).is_err(),
                "{} should be protected",
                protected
            );
        }
        assert!(policy.check(ip("203.0.113.9")).is_ok());
        assert!(policy.check(ip("2001:db8::9")).is_ok());
    }

    #[test]
    fn operator_ranges_and_mapped_addresses_are_protected() {
        let mut policy = BlockPolicy::builtin();
        policy.protect(
            "10.20.0.0/16".parse().unwrap(),
            "operator never-block range",
        );
        policy.protect_ip(ip("198.51.100.7"), "mesh peer");
        assert_eq!(
            policy.check(ip("10.20.3.4")),
            Err("operator never-block range")
        );
        assert_eq!(policy.check(ip("::ffff:198.51.100.7")), Err("mesh peer"));
        assert!(policy.check(ip("10.21.0.1")).is_ok());
    }

    #[test]
    fn prefixes_must_not_cover_protected_addresses_or_be_too_wide() {
        let mut policy = BlockPolicy::builtin();
        policy.protect_ip(ip("10.231.0.1"), LOCAL_ADDRESS);
        policy.protect(
            "192.0.2.0/28".parse().unwrap(),
            "operator never-block range",
        );
        let net = |s: &str| s.parse::<IpNet>().unwrap();

        assert_eq!(policy.check_net(net("198.51.100.0/24")), Ok(()));
        assert_eq!(
            policy.check_net(net("10.231.0.0/24")),
            Err(LOCAL_ADDRESS),
            "contains this node"
        );
        assert_eq!(
            policy.check_net(net("192.0.2.0/29")),
            Err("operator never-block range"),
            "inside a protected range"
        );
        assert_eq!(
            policy.check_net(net("192.0.2.0/24")),
            Err("operator never-block range"),
            "covers a protected range"
        );
        assert_eq!(policy.check_net(net("127.0.0.0/16")), Err("loopback"));
        // Strictly inside a protected range, not containing its network address.
        assert_eq!(
            policy.check_net(net("192.0.2.8/29")),
            Err("operator never-block range")
        );
        assert_eq!(policy.check_net(net("127.1.0.0/16")), Err("loopback"));
        assert_eq!(policy.check_net(net("198.0.0.0/8")), Err(PREFIX_TOO_WIDE));
        assert_eq!(policy.check_net(net("2001:db8::/32")), Err(PREFIX_TOO_WIDE));
        assert_eq!(policy.check_net(net("2001:db8:1::/48")), Ok(()));
        assert_eq!(
            policy.check_net(net("10.231.0.1/32")),
            Err(LOCAL_ADDRESS),
            "hosts use the address check"
        );

        policy.set_min_prefix(8, 32);
        assert_eq!(policy.check_net(net("198.0.0.0/8")), Ok(()));
    }

    #[test]
    fn parses_default_gateways_from_proc() {
        let v4 = "Iface\tDestination\tGateway \tFlags\n\
                  eth0\t00000000\t0100000A\t0003\n\
                  eth0\t0000000A\t00000000\t0001\n";
        assert_eq!(parse_ipv4_default_gateways(v4), vec![ip("10.0.0.1")]);

        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n\
                  20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n";
        assert_eq!(parse_ipv6_default_gateways(v6), vec![ip("fe80::1")]);
    }
}
