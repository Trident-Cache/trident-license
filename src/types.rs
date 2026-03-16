//! License data types.

use serde::{Deserialize, Serialize};

/// A Trident product license.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// Schema version (currently 1)
    pub version: u32,

    /// Product identifier ("trident-cache", "prism", etc.)
    #[serde(default = "default_product")]
    pub product: String,

    /// Unique license identifier
    pub license_id: String,

    /// Customer information
    pub customer: LicenseCustomer,

    /// License type
    pub license_type: LicenseType,

    /// When the license was issued (RFC 3339)
    pub issued_at: String,

    /// When the license expires (RFC 3339), if applicable
    #[serde(default)]
    pub expires_at: Option<String>,

    /// Maximum number of instances (0 = unlimited)
    #[serde(default)]
    pub max_instances: u32,

    /// Enabled features (reserved for future use)
    #[serde(default)]
    pub features: Vec<String>,
}

fn default_product() -> String {
    "trident-cache".to_string()
}

/// Customer information embedded in a license.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCustomer {
    /// Customer name
    pub name: String,

    /// Customer email
    pub email: String,
}

/// Type of license.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseType {
    /// 14-day trial license
    Trial,
    /// Paid commercial license with expiry
    Commercial,
    /// Perpetual license (no expiry)
    Perpetual,
}

/// Current status of the license.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus {
    /// Valid commercial or perpetual license
    Valid,
    /// Valid trial license (time-limited)
    Trial,
    /// License has expired
    Expired,
    /// No license file configured
    NoLicense,
    /// License file is invalid (tampered, malformed, etc.)
    Invalid,
}

impl LicenseStatus {
    /// Whether the license allows full operation.
    pub const fn is_operational(&self) -> bool {
        matches!(self, Self::Valid | Self::Trial)
    }

    /// Header value for license status response headers.
    ///
    /// Returns `None` for `Valid` (no header needed when fully licensed).
    pub const fn header_value(&self) -> Option<&'static str> {
        match self {
            Self::Valid => None,
            Self::Trial => Some("trial"),
            Self::Expired => Some("expired"),
            Self::NoLicense => Some("unlicensed"),
            Self::Invalid => Some("invalid"),
        }
    }
}

impl std::fmt::Display for LicenseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trial => write!(f, "trial"),
            Self::Commercial => write!(f, "commercial"),
            Self::Perpetual => write!(f, "perpetual"),
        }
    }
}

impl std::fmt::Display for LicenseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Trial => write!(f, "trial"),
            Self::Expired => write!(f, "expired"),
            Self::NoLicense => write!(f, "no_license"),
            Self::Invalid => write!(f, "invalid"),
        }
    }
}
