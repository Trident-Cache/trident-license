//! Runtime license management with date checks on every access.

#[cfg(feature = "licensing")]
mod licensed {
    use crate::types::{License, LicenseStatus, LicenseType};
    use crate::verifier::{LicenseError, LicenseVerifier};
    use chrono::{DateTime, Utc};
    use parking_lot::RwLock;
    use std::path::Path;
    use tracing::{info, warn};

    // Publish status and expiry together so concurrent reloads cannot mix
    // entitlement state from one licence with dates from another.
    struct State {
        status: LicenseStatus,
        expires: Option<DateTime<Utc>>,
    }

    impl State {
        fn from_license(license: &License) -> Self {
            if license.license_type == LicenseType::Perpetual {
                return Self {
                    status: LicenseStatus::Valid,
                    expires: None,
                };
            }
            let expires = match license.expires_at.as_deref() {
                Some(value) => match DateTime::parse_from_rfc3339(value) {
                    Ok(date) => Some(date.with_timezone(&Utc)),
                    Err(_) => {
                        return Self {
                            status: LicenseStatus::Expired,
                            expires: None,
                        }
                    }
                },
                None => None,
            };
            Self {
                status: if license.license_type == LicenseType::Trial {
                    LicenseStatus::Trial
                } else {
                    LicenseStatus::Valid
                },
                expires,
            }
        }

        fn status_at(&self, now: DateTime<Utc>) -> LicenseStatus {
            if self.status.is_operational() && self.expires.is_some_and(|date| now >= date) {
                LicenseStatus::Expired
            } else {
                self.status
            }
        }
    }

    /// Checks the cached, verified expiry on every licence access. No file I/O
    /// or signature verification is performed on the request path.
    pub struct LicenseManager {
        state: RwLock<State>,
        public_key: [u8; 32],
    }

    impl LicenseManager {
        pub fn new(path: Option<&Path>, public_key: &[u8; 32]) -> Self {
            let manager = Self::unlicensed(public_key);
            if let Some(path) = path {
                if let Err(error) = manager.reload(path) {
                    warn!(%error, path = %path.display(), "Failed to load license file");
                }
            }
            manager
        }

        pub fn unlicensed(public_key: &[u8; 32]) -> Self {
            Self {
                state: RwLock::new(State {
                    status: LicenseStatus::NoLicense,
                    expires: None,
                }),
                public_key: *public_key,
            }
        }

        #[inline]
        pub fn is_licensed(&self) -> bool {
            self.status().is_operational()
        }

        pub fn status(&self) -> LicenseStatus {
            self.state.read().status_at(Utc::now())
        }

        pub fn header_value(&self) -> Option<&'static str> {
            self.status().header_value()
        }

        /// Reload atomically. Any read, signature or payload error revokes the
        /// previous entitlement immediately; a valid replacement restores it.
        pub fn reload(&self, path: &Path) -> Result<(), LicenseError> {
            let mut state = self.state.write();
            match LicenseVerifier::verify_file(path, &self.public_key) {
                Ok(license) => {
                    *state = State::from_license(&license);
                    Ok(())
                }
                Err(error) => {
                    *state = State {
                        status: LicenseStatus::Invalid,
                        expires: None,
                    };
                    Err(error)
                }
            }
        }

        pub fn mark_expired(&self) {
            *self.state.write() = State {
                status: LicenseStatus::Expired,
                expires: None,
            };
        }

        pub fn log_status(&self) {
            let state = self.state.read();
            let now = Utc::now();
            match state.status_at(now) {
                LicenseStatus::Valid => {
                    info!(expires = ?state.expires, "License validated successfully")
                }
                LicenseStatus::Trial => {
                    let remaining = state
                        .expires
                        .map(|expires| (expires - now).num_days())
                        .unwrap_or(0);
                    warn!(days_remaining = remaining, "Trial license active");
                }
                LicenseStatus::Expired => warn!("License expired - running in degraded mode"),
                LicenseStatus::NoLicense => {
                    warn!("No license file configured - running in degraded mode")
                }
                LicenseStatus::Invalid => warn!("Invalid license file - running in degraded mode"),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn expiry_is_inclusive_and_applies_to_trials_and_commercial_licenses() {
            let expiry = Utc::now();
            for status in [LicenseStatus::Trial, LicenseStatus::Valid] {
                let state = State {
                    status,
                    expires: Some(expiry),
                };
                assert_eq!(
                    state.status_at(expiry - chrono::Duration::nanoseconds(1)),
                    status
                );
                assert_eq!(state.status_at(expiry), LicenseStatus::Expired);
                assert_eq!(
                    state.status_at(expiry + chrono::Duration::days(3650)),
                    LicenseStatus::Expired
                );
            }
        }
    }
}

#[cfg(not(feature = "licensing"))]
mod unlicensed {
    use std::path::Path;

    use tracing::info;

    use crate::types::LicenseStatus;
    use crate::verifier::LicenseError;

    /// No-op license manager when the `licensing` feature is disabled.
    ///
    /// All checks return "licensed" — full functionality is always enabled.
    pub struct LicenseManager;

    impl LicenseManager {
        pub fn new(_path: Option<&Path>, _public_key: &[u8; 32]) -> Self {
            Self
        }

        pub fn unlicensed(_public_key: &[u8; 32]) -> Self {
            Self
        }

        #[inline]
        pub fn is_licensed(&self) -> bool {
            true
        }

        pub fn status(&self) -> LicenseStatus {
            LicenseStatus::Valid
        }

        pub fn header_value(&self) -> Option<&'static str> {
            None
        }

        pub fn reload(&self, _path: &Path) -> Result<(), LicenseError> {
            Ok(())
        }

        pub fn mark_expired(&self) {}

        pub fn log_status(&self) {
            info!("Licensing disabled at build time — all features enabled");
        }
    }
}

#[cfg(feature = "licensing")]
pub use licensed::LicenseManager;

#[cfg(not(feature = "licensing"))]
pub use unlicensed::LicenseManager;
