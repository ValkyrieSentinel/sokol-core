//! Typed protection identity; diagnostic wording does not choose a detector's target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionReason {
    Loopback,
    Unspecified,
    Broadcast,
    Multicast,
    Ipv6LinkLocal,
    LocalAddress,
    HomeNetwork,
    DefaultGateway,
    WireGuardEndpoint,
    MeshSeedPeer,
    OperatorNeverBlock,
    PrefixTooWide,
    #[cfg(test)]
    Diagnostic(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRole {
    LocalSide,
    ProtectedOther,
}

impl ProtectionReason {
    pub const fn source_role(self) -> SourceRole {
        match self {
            Self::LocalAddress | Self::HomeNetwork => SourceRole::LocalSide,
            Self::Loopback
            | Self::Unspecified
            | Self::Broadcast
            | Self::Multicast
            | Self::Ipv6LinkLocal
            | Self::DefaultGateway
            | Self::WireGuardEndpoint
            | Self::MeshSeedPeer
            | Self::OperatorNeverBlock
            | Self::PrefixTooWide => SourceRole::ProtectedOther,
            #[cfg(test)]
            Self::Diagnostic(_) => SourceRole::ProtectedOther,
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Unspecified => "unspecified address",
            Self::Broadcast => "broadcast",
            Self::Multicast => "multicast",
            Self::Ipv6LinkLocal => "IPv6 link-local",
            Self::LocalAddress => "address of this node",
            Self::HomeNetwork => "home network (--home-net)",
            Self::DefaultGateway => "default gateway",
            Self::WireGuardEndpoint => "WireGuard peer endpoint",
            Self::MeshSeedPeer => "mesh seed peer",
            Self::OperatorNeverBlock => "operator never-block range",
            Self::PrefixTooWide => "prefix wider than --min-block-prefix-v4/-v6 allows",
            #[cfg(test)]
            Self::Diagnostic(text) => text,
        }
    }
}

impl std::fmt::Display for ProtectionReason {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.description())
    }
}

// Compatibility for the already owner-pinned test bodies. Production has no string-to-kind
// conversion: constructors must name an enum variant, and target selection uses its role.
#[cfg(test)]
impl From<&'static str> for ProtectionReason {
    fn from(text: &'static str) -> Self {
        match text {
            "address of this node" => Self::LocalAddress,
            "home network (--home-net)" => Self::HomeNetwork,
            "WireGuard peer endpoint" => Self::WireGuardEndpoint,
            "default gateway" => Self::DefaultGateway,
            _ => Self::Diagnostic(text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_fixture_labels_keep_their_typed_protection_identity() {
        for (text, reason) in [
            ("address of this node", ProtectionReason::LocalAddress),
            ("home network (--home-net)", ProtectionReason::HomeNetwork),
            (
                "WireGuard peer endpoint",
                ProtectionReason::WireGuardEndpoint,
            ),
            ("default gateway", ProtectionReason::DefaultGateway),
        ] {
            assert_eq!(ProtectionReason::from(text), reason);
        }
        assert_eq!(
            ProtectionReason::from("test"),
            ProtectionReason::Diagnostic("test")
        );
    }

    #[test]
    fn only_local_and_home_protection_name_the_remote_destination() {
        for (reason, role, text) in [
            (
                ProtectionReason::Loopback,
                SourceRole::ProtectedOther,
                "loopback",
            ),
            (
                ProtectionReason::Unspecified,
                SourceRole::ProtectedOther,
                "unspecified address",
            ),
            (
                ProtectionReason::Broadcast,
                SourceRole::ProtectedOther,
                "broadcast",
            ),
            (
                ProtectionReason::Multicast,
                SourceRole::ProtectedOther,
                "multicast",
            ),
            (
                ProtectionReason::Ipv6LinkLocal,
                SourceRole::ProtectedOther,
                "IPv6 link-local",
            ),
            (
                ProtectionReason::LocalAddress,
                SourceRole::LocalSide,
                "address of this node",
            ),
            (
                ProtectionReason::HomeNetwork,
                SourceRole::LocalSide,
                "home network (--home-net)",
            ),
            (
                ProtectionReason::DefaultGateway,
                SourceRole::ProtectedOther,
                "default gateway",
            ),
            (
                ProtectionReason::WireGuardEndpoint,
                SourceRole::ProtectedOther,
                "WireGuard peer endpoint",
            ),
            (
                ProtectionReason::MeshSeedPeer,
                SourceRole::ProtectedOther,
                "mesh seed peer",
            ),
            (
                ProtectionReason::OperatorNeverBlock,
                SourceRole::ProtectedOther,
                "operator never-block range",
            ),
            (
                ProtectionReason::PrefixTooWide,
                SourceRole::ProtectedOther,
                "prefix wider than --min-block-prefix-v4/-v6 allows",
            ),
        ] {
            assert_eq!(reason.source_role(), role, "{reason:?}");
            assert_eq!(reason.description(), text);
            assert_eq!(reason.to_string(), text);
        }
    }

    #[test]
    fn matching_diagnostic_text_does_not_grant_local_source_authority() {
        for reason in [
            ProtectionReason::LocalAddress,
            ProtectionReason::HomeNetwork,
        ] {
            let diagnostic = ProtectionReason::Diagnostic(reason.description());
            assert_eq!(diagnostic.description(), reason.description());
            assert_eq!(diagnostic.source_role(), SourceRole::ProtectedOther);
            assert_eq!(reason.source_role(), SourceRole::LocalSide);
        }
    }
}
