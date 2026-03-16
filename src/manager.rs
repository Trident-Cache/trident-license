//! License management with atomic fast-path checks.

#[cfg(feature = "licensing")]
mod licensed {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    use parking_lot::RwLock;
    use tracing::{info, warn};

    use crate::types::{License, LicenseStatus, LicenseType};
    use crate::verifier::{LicenseError, LicenseVerifier};

    /// Manages license state with a fast atomic check path.
    ///
    /// The `is_licensed()` method uses an `AtomicBool` for near-zero overhead
    /// on the hot request path. Detailed status is behind a `RwLock` for
    /// logging and header injection.
    pub struct LicenseManager {
        licensed: AtomicBool,
        status: RwLock<LicenseStatus>,
        license: RwLock<Option<License>>,
        public_key: [u8; 32],
    }

    impl LicenseManager {
        /// Create a new LicenseManager by loading and verifying a license file.
        ///
        /// If `path` is `None`, returns an unlicensed manager.
        pub fn new(path: Option<&Path>, public_key: &[u8; 32]) -> Self {
            let Some(path) = path else {
                return Self::unlicensed(public_key);
            };

            match LicenseVerifier::verify_file(path, public_key) {
                Ok(license) => {
                    let status = Self::determine_status(&license);
                    let licensed = status.is_operational();

                    Self {
                        licensed: AtomicBool::new(licensed),
                        status: RwLock::new(status),
                        license: RwLock::new(Some(license)),
                        public_key: *public_key,
                    }
                }
                Err(e) => {
                    warn!(error = %e, path = %path.display(), "Failed to load license file");
                    Self {
                        licensed: AtomicBool::new(false),
                        status: RwLock::new(LicenseStatus::Invalid),
                        license: RwLock::new(None),
                        public_key: *public_key,
                    }
                }
            }
        }

        /// Create an unlicensed manager.
        pub fn unlicensed(public_key: &[u8; 32]) -> Self {
            Self {
                licensed: AtomicBool::new(false),
                status: RwLock::new(LicenseStatus::NoLicense),
                license: RwLock::new(None),
                public_key: *public_key,
            }
        }

        /// Fast-path license check (~0 cost per request).
        #[inline]
        pub fn is_licensed(&self) -> bool {
            self.licensed.load(Ordering::Relaxed)
        }

        /// Get the detailed license status.
        pub fn status(&self) -> LicenseStatus {
            *self.status.read()
        }

        /// Get the header value for license status response headers.
        ///
        /// Returns `None` when the license is valid (no header needed).
        pub fn header_value(&self) -> Option<&'static str> {
            self.status.read().header_value()
        }

        /// Reload the license from a file path.
        pub fn reload(&self, path: &Path) -> Result<(), LicenseError> {
            let license = LicenseVerifier::verify_file(path, &self.public_key)?;
            let status = Self::determine_status(&license);
            let licensed = status.is_operational();

            self.licensed.store(licensed, Ordering::Relaxed);
            *self.status.write() = status;
            *self.license.write() = Some(license);

            Ok(())
        }

        /// Log the current license status at startup.
        pub fn log_status(&self) {
            let status = *self.status.read();
            let license = self.license.read();

            match status {
                LicenseStatus::Valid => {
                    if let Some(ref lic) = *license {
                        if let Some(ref expires) = lic.expires_at {
                            info!(
                                license_type = %lic.license_type,
                                expires = %expires,
                                "License validated successfully"
                            );
                        } else {
                            info!(
                                license_type = %lic.license_type,
                                "License validated successfully (no expiry)"
                            );
                        }
                    }
                }
                LicenseStatus::Trial => {
                    if let Some(ref lic) = *license {
                        let remaining = Self::days_remaining(lic);
                        warn!(days_remaining = remaining, "Trial license active");
                    }
                }
                LicenseStatus::Expired => {
                    warn!("License expired - running in degraded mode");
                }
                LicenseStatus::NoLicense => {
                    warn!("No license file configured - running in degraded mode");
                }
                LicenseStatus::Invalid => {
                    warn!("Invalid license file - running in degraded mode");
                }
            }
        }

        fn determine_status(license: &License) -> LicenseStatus {
            if license.license_type == LicenseType::Perpetual {
                return LicenseStatus::Valid;
            }

            if let Some(ref expires_at) = license.expires_at {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                    let now = chrono::Utc::now();
                    let expires_utc = expires.with_timezone(&chrono::Utc);
                    if now >= expires_utc {
                        return LicenseStatus::Expired;
                    }
                } else {
                    return LicenseStatus::Expired;
                }
            }

            match license.license_type {
                LicenseType::Trial => LicenseStatus::Trial,
                LicenseType::Commercial => LicenseStatus::Valid,
                LicenseType::Perpetual => LicenseStatus::Valid,
            }
        }

        fn days_remaining(license: &License) -> i64 {
            license
                .expires_at
                .as_deref()
                .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
                .map(|expires| {
                    let now = chrono::Utc::now();
                    let expires_utc = expires.with_timezone(&chrono::Utc);
                    (expires_utc - now).num_days()
                })
                .unwrap_or(0)
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

        pub fn log_status(&self) {
            info!("Licensing disabled at build time — all features enabled");
        }
    }
}

#[cfg(feature = "licensing")]
pub use licensed::LicenseManager;

#[cfg(not(feature = "licensing"))]
pub use unlicensed::LicenseManager;
