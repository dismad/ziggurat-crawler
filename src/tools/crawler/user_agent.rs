use std::{collections::BTreeMap, fmt, net::SocketAddr};

/// Node implementation advertised in a BIP-14 user agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImplKind {
    Zebra,
    Zakura,
}

/// `major.minor.patch` taken from a user agent. Pre-release suffixes are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for NodeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Classify a Zcash `version` user agent.
///
/// Matches `/Zebra:7.1.0/`, `/zakura:1.6.1/`, and the same tokens with a space
/// instead of a colon. Case-insensitive. The earliest token wins.
pub fn classify(user_agent: &str) -> Option<(ImplKind, NodeVersion)> {
    let mut best: Option<(usize, ImplKind, NodeVersion)> = None;
    for (kind, prefixes) in [
        (ImplKind::Zebra, ["zebra:", "zebra "].as_slice()),
        (ImplKind::Zakura, ["zakura:", "zakura "].as_slice()),
    ] {
        if let Some((at, version)) = find_version(user_agent, prefixes) {
            let replace = match best {
                Some((prev, _, _)) => at < prev,
                None => true,
            };
            if replace {
                best = Some((at, kind, version));
            }
        }
    }
    best.map(|(_, kind, version)| (kind, version))
}

pub fn is_zebra_at_least_7(kind: ImplKind, version: NodeVersion) -> bool {
    kind == ImplKind::Zebra && version.major >= 7
}

fn find_version(user_agent: &str, prefixes: &[&str]) -> Option<(usize, NodeVersion)> {
    let lower = user_agent.to_ascii_lowercase();
    let mut found: Option<(usize, NodeVersion)> = None;
    for prefix in prefixes {
        let mut search_from = 0;
        while let Some(rel) = lower[search_from..].find(prefix) {
            let start = search_from + rel;
            let boundary_ok =
                start == 0 || matches!(lower.as_bytes()[start - 1], b'/' | b' ' | b'(' | b'[');
            if boundary_ok {
                let rest = &user_agent[start + prefix.len()..];
                if let Some(version) = parse_version(rest) {
                    let replace = match found {
                        Some((prev_at, _)) => start < prev_at,
                        None => true,
                    };
                    if replace {
                        found = Some((start, version));
                    }
                }
            }
            search_from = start + prefix.len();
            if search_from >= lower.len() {
                break;
            }
        }
    }
    found
}

fn parse_version(s: &str) -> Option<NodeVersion> {
    let s = s.trim_start_matches(|c: char| c == '/' || c.is_whitespace());
    let major = take_u32(s)?;
    let mut rest = &s[major.1..];
    let mut minor = 0;
    let mut patch = 0;
    if let Some(next) = rest.strip_prefix('.') {
        let parsed = take_u32(next)?;
        minor = parsed.0;
        rest = &next[parsed.1..];
        if let Some(next) = rest.strip_prefix('.') {
            if let Some(parsed) = take_u32(next) {
                patch = parsed.0;
            }
        }
    }
    Some(NodeVersion {
        major: major.0,
        minor,
        patch,
    })
}

fn take_u32(s: &str) -> Option<(u32, usize)> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let value = digits.parse().ok()?;
    Some((value, digits.len()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplHit {
    pub addr: SocketAddr,
    pub version: NodeVersion,
}

/// Zebra 7+ peers, and Zakura peers grouped so the newest release is obvious.
#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    pub zebra_7: Vec<ImplHit>,
    pub newest_zakura: Option<NodeVersion>,
    pub newest_zakura_peers: Vec<ImplHit>,
    pub older_zakura: BTreeMap<NodeVersion, Vec<SocketAddr>>,
}

impl TargetSet {
    pub fn from_nodes<'a, I>(nodes: I) -> Self
    where
        I: IntoIterator<Item = (&'a SocketAddr, &'a crate::network::KnownNode)>,
    {
        let mut zebra_7 = Vec::new();
        let mut zakura: BTreeMap<NodeVersion, Vec<SocketAddr>> = BTreeMap::new();
        for (addr, node) in nodes {
            let Some((kind, version)) = node.impl_version() else {
                continue;
            };
            match kind {
                ImplKind::Zebra if version.major >= 7 => zebra_7.push(ImplHit {
                    addr: *addr,
                    version,
                }),
                ImplKind::Zakura => zakura.entry(version).or_default().push(*addr),
                ImplKind::Zebra => {}
            }
        }
        zebra_7.sort_by(|a, b| b.version.cmp(&a.version).then(a.addr.cmp(&b.addr)));
        let newest_zakura = zakura.keys().next_back().copied();
        let newest_zakura_peers = newest_zakura
            .and_then(|v| zakura.remove(&v))
            .unwrap_or_default()
            .into_iter()
            .map(|addr| ImplHit {
                addr,
                version: newest_zakura.unwrap(),
            })
            .collect();
        Self {
            zebra_7,
            newest_zakura,
            newest_zakura_peers,
            older_zakura: zakura,
        }
    }

    pub fn report(&self) -> String {
        let mut zebra_counts: BTreeMap<NodeVersion, usize> = BTreeMap::new();
        for hit in &self.zebra_7 {
            *zebra_counts.entry(hit.version).or_default() += 1;
        }
        let zebra = if zebra_counts.is_empty() {
            "none".to_string()
        } else {
            zebra_counts
                .iter()
                .rev()
                .map(|(v, n)| format!("{v} x{n}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let zebra_addrs = preview(self.zebra_7.iter().map(|h| h.addr));
        let zakura = match self.newest_zakura {
            Some(v) => format!("{v} x{}", self.newest_zakura_peers.len()),
            None => "none".to_string(),
        };
        let zakura_addrs = preview(self.newest_zakura_peers.iter().map(|h| h.addr));
        let older = if self.older_zakura.is_empty() {
            String::new()
        } else {
            let parts = self
                .older_zakura
                .iter()
                .rev()
                .map(|(v, addrs)| format!("{v} x{}", addrs.len()))
                .collect::<Vec<_>>()
                .join(", ");
            format!("; older zakura: {parts}")
        };
        format!(
            "zebra>=7: {zebra} [{zebra_addrs}]; newest zakura: {zakura} [{zakura_addrs}]{older}"
        )
    }
}

fn preview<I>(addrs: I) -> String
where
    I: IntoIterator<Item = SocketAddr>,
{
    const LIMIT: usize = 8;
    let addrs: Vec<_> = addrs.into_iter().take(LIMIT + 1).collect();
    if addrs.is_empty() {
        return "-".to_string();
    }
    let more = addrs.len() > LIMIT;
    let shown = addrs
        .into_iter()
        .take(LIMIT)
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if more {
        format!("{shown}, ...")
    } else {
        shown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_zebra_7_and_zakura() {
        assert_eq!(
            classify("/Zebra:7.1.0/"),
            Some((
                ImplKind::Zebra,
                NodeVersion {
                    major: 7,
                    minor: 1,
                    patch: 0
                }
            ))
        );
        assert_eq!(
            classify("/zakura:1.6.1/"),
            Some((
                ImplKind::Zakura,
                NodeVersion {
                    major: 1,
                    minor: 6,
                    patch: 1
                }
            ))
        );
        assert_eq!(
            classify("/Zakura:1.6.1/"),
            Some((
                ImplKind::Zakura,
                NodeVersion {
                    major: 1,
                    minor: 6,
                    patch: 1
                }
            ))
        );
        assert_eq!(classify("/Zebra:6.4.0/").unwrap().1.major, 6);
        assert!(classify("/MagicBean:5.10.0/").is_none());
        assert!(is_zebra_at_least_7(
            ImplKind::Zebra,
            NodeVersion {
                major: 7,
                minor: 0,
                patch: 0
            }
        ));
        assert!(!is_zebra_at_least_7(
            ImplKind::Zebra,
            NodeVersion {
                major: 6,
                minor: 4,
                patch: 0
            }
        ));
    }

    #[test]
    fn newest_zakura_is_highest_semver() {
        assert!(
            NodeVersion {
                major: 1,
                minor: 6,
                patch: 1
            } > NodeVersion {
                major: 1,
                minor: 3,
                patch: 0
            }
        );
    }
}
