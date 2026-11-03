use crate::config::invalid;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io, net::IpAddr};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Policy {
    Disabled(Disabled),
    Allow(Allow),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Disabled {
    None,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    pub allow: Vec<String>,
}

impl Policy {
    pub fn sdk(&self) -> serde_json::Value {
        let rules = match self {
            Self::Disabled(_) => Vec::new(),
            Self::Allow(policy) => policy.allow.iter().map(|name|
                serde_json::json!({"action":"allow","target":name.trim_end_matches('.').to_ascii_lowercase()})
            ).collect(),
        };
        serde_json::json!({"defaultAction":"deny","egress":rules})
    }

    pub fn enabled(&self) -> bool {
        matches!(self, Self::Allow(_))
    }

    pub fn validate(&self) -> io::Result<()> {
        let Self::Allow(policy) = self else {
            return Ok(());
        };
        if !(1..=256).contains(&policy.allow.len()) {
            return Err(invalid("Network allow needs 1..256 distinct DNS names"));
        }
        let mut seen = HashSet::new();
        for value in &policy.allow {
            if !seen.insert(domain(value)?) {
                return Err(invalid("Network allow has a duplicate DNS name"));
            }
        }
        Ok(())
    }

    pub fn permits(&self, name: &str) -> bool {
        let Self::Allow(policy) = self else {
            return false;
        };
        policy
            .allow
            .iter()
            .any(|value| value.trim_end_matches('.').eq_ignore_ascii_case(name))
    }
}

/// Exact ASCII DNS names, including explicitly supplied A-labels. There is no
/// wildcard, suffix, URI, search-domain or numeric-address interpretation.
pub fn domain(value: &str) -> io::Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.len() > 253
        || !value.contains('.')
        || value.parse::<IpAddr>().is_ok()
        || !value
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().any(|b| b.is_ascii_alphabetic()))
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid("PROXY_INVALID_DOMAIN"));
    }
    Ok(value.to_ascii_lowercase())
}

/// Egress accepts public unicast destinations. A DNS name must never turn an
/// allowlist entry into access to local services, metadata or translation ranges.
pub fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127)
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && matches!(c, 0 | 2)) || (b == 88 && c == 99)))
                || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let [a, b, _, _, _, _, _, _] = ip.segments();
            // Current globally allocated unicast space, excluding protocol
            // assignments, documentation, 6to4 and segment-routing SIDs.
            (a & 0xe000 == 0x2000)
                && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
                && a != 0x2002
                && (a & 0xfff0 != 0x3ff0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_matches_exact_normalized_names_and_refuses_ambiguous_forms() {
        let policy: Policy =
            serde_json::from_str(r#"{"allow":["PyPI.org.","files.pythonhosted.org"]}"#).unwrap();
        policy.validate().unwrap();
        assert_eq!(
            policy.sdk(),
            serde_json::json!({"defaultAction":"deny","egress":[
                {"action":"allow","target":"pypi.org"}, {"action":"allow","target":"files.pythonhosted.org"}
            ]})
        );
        assert!(policy.permits(&domain("PYPI.ORG").unwrap()));
        for denied in ["evilpypi.org", "pypi.org.evil.test", "www.pypi.org"] {
            assert!(!policy.permits(denied));
        }
        for bad in [
            "",
            "localhost",
            "127.0.0.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "[::1]",
            "https://pypi.org",
            "user@pypi.org",
            "*.pypi.org",
            "pypi.org:443",
            "pypi..org",
            "pypi.org..",
            "-pypi.org",
            "pypi-.org",
            "pypi.org\r\n",
            "例子.org",
        ] {
            assert!(domain(bad).is_err(), "accepted {bad:?}");
        }
        for bad in [r#""host""#, r#"{"allow":["pypi.org"],"host":true}"#] {
            assert!(serde_json::from_str::<Policy>(bad).is_err());
        }
        for bad in [r#"{"allow":[]}"#, r#"{"allow":["pypi.org","PYPI.ORG."]}"#] {
            assert!(
                serde_json::from_str::<Policy>(bad)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }

    #[test]
    fn dns_cannot_authorize_local_special_or_embedded_addresses() {
        for allowed in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(public_address(allowed.parse().unwrap()));
        }
        for denied in [
            "0.0.0.0",
            "10.1.2.3",
            "100.100.100.200",
            "127.1.2.3",
            "169.254.169.254",
            "172.16.1.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.1.1.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "2001::1",
            "3fff::1",
        ] {
            assert!(
                !public_address(denied.parse().unwrap()),
                "accepted {denied}"
            );
        }
    }
}
