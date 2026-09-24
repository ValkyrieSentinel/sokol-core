//! Addresses the node must never drop, whoever asks: an automatic block of the node itself,
//! its gateway, its mesh peers or the operator's network would cut the node off.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Reason given for this host's own interface addresses.
pub const LOCAL_ADDRESS: &str = "address of this node";

pub struct BlockPolicy {
    protected: Vec<(IpNet, &'static str)>,
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
                .map(|(net, why)| (net.parse().expect("builtin CIDR"), *why))
                .collect(),
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

    /// Adds every address configured on this host's interfaces and its default gateways.
    pub fn protect_host_addresses(&mut self) {
        for ip in local_interface_addresses() {
            self.protect_ip(ip, LOCAL_ADDRESS);
        }
        for ip in default_gateways() {
            self.protect_ip(ip, "default gateway");
        }
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

fn local_interface_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list that we walk read-only and release with freeifaddrs.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            log::warn!(
                "[BlockPolicy] getifaddrs failed; this node's own addresses are not protected"
            );
            return out;
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
    out
}

fn default_gateways() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(table) = std::fs::read_to_string("/proc/net/route") {
        out.extend(parse_ipv4_default_gateways(&table));
    }
    if let Ok(table) = std::fs::read_to_string("/proc/net/ipv6_route") {
        out.extend(parse_ipv6_default_gateways(&table));
    }
    out
}

/// `/proc/net/route`: Iface Destination Gateway ... in little-endian hex.
fn parse_ipv4_default_gateways(table: &str) -> Vec<IpAddr> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 || cols[1] != "00000000" {
                return None;
            }
            let gw = u32::from_str_radix(cols[2], 16).ok()?;
            (gw != 0).then(|| IpAddr::V4(Ipv4Addr::from(u32::from_be(gw))))
        })
        .collect()
}

/// `/proc/net/ipv6_route`: dest dest_len src src_len next_hop ... in big-endian hex.
fn parse_ipv6_default_gateways(table: &str) -> Vec<IpAddr> {
    table
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 || cols[1] != "00" || cols[0].chars().any(|c| c != '0') {
                return None;
            }
            let hop = u128::from_str_radix(cols[4], 16).ok()?;
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
