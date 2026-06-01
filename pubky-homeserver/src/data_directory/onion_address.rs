use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Validated Tor v3 hidden-service hostname (`{56 base32 chars}.onion`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionAddress(pub String);

impl OnionAddress {
    /// Create from a string after validating v3 onion format.
    pub fn new(address: String) -> Result<Self, anyhow::Error> {
        Self::validate(&address)?;
        Ok(Self(address))
    }

    /// Validate a Tor v3 onion hostname.
    pub fn validate(address: &str) -> anyhow::Result<()> {
        let host = address.strip_suffix(".onion").ok_or_else(|| {
            anyhow::anyhow!("Invalid onion address '{address}': must end with .onion")
        })?;
        if host.len() != 56 {
            return Err(anyhow::anyhow!(
                "Invalid onion address '{address}': v3 host label must be 56 characters, got {}",
                host.len()
            ));
        }
        if !host.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')) {
            return Err(anyhow::anyhow!(
                "Invalid onion address '{address}': host must be base32 (a-z, 2-7)"
            ));
        }
        Ok(())
    }
}

impl FromStr for OnionAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.trim().to_string())
    }
}

impl Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for OnionAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OnionAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

    #[test]
    fn valid_v3_onion() {
        assert!(OnionAddress::from_str(VALID).is_ok());
    }

    #[test]
    fn rejects_short_host() {
        assert!(OnionAddress::from_str("abc.onion").is_err());
    }
}
