//! Ed25519 license verification.

#[cfg(feature = "licensing")]
use base64::Engine;
#[cfg(feature = "licensing")]
use ring::signature;

#[cfg(feature = "licensing")]
use crate::types::License;

/// Errors that can occur during license verification.
#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    /// License file not found at the configured path.
    #[error("license file not found: {0}")]
    FileNotFound(String),

    /// License file format is invalid (missing `.` separator).
    #[error("malformed license file: expected <payload>.<signature> format")]
    MalformedFile,

    /// Base64 decoding failed.
    #[error("invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Ed25519 signature verification failed.
    #[error("invalid license signature")]
    InvalidSignature,

    /// JSON payload could not be parsed into a License.
    #[error("invalid license payload: {0}")]
    InvalidPayload(String),

    /// License schema version is not supported.
    #[error("unsupported license version: {0}")]
    UnsupportedVersion(u32),

    /// I/O error reading the license file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// License verifier using Ed25519 signatures.
///
/// No public key is embedded — consumers must provide their own.
pub struct LicenseVerifier;

#[cfg(feature = "licensing")]
impl LicenseVerifier {
    /// Verify a license string using the provided Ed25519 public key.
    ///
    /// The data format is: `<base64-json-payload>.<base64-ed25519-signature>`
    pub fn verify(data: &str, public_key: &[u8; 32]) -> Result<License, LicenseError> {
        let data = data.trim();

        // Split into payload and signature
        let (payload_b64, sig_b64) = data.rsplit_once('.').ok_or(LicenseError::MalformedFile)?;

        if payload_b64.is_empty() || sig_b64.is_empty() {
            return Err(LicenseError::MalformedFile);
        }

        let engine = base64::engine::general_purpose::STANDARD;

        // Decode base64 payload
        let payload_bytes = engine
            .decode(payload_b64)
            .map_err(|e| LicenseError::InvalidBase64(format!("payload: {e}")))?;

        // Decode base64 signature
        let sig_bytes = engine
            .decode(sig_b64)
            .map_err(|e| LicenseError::InvalidBase64(format!("signature: {e}")))?;

        // Verify Ed25519 signature over the raw base64-encoded payload string
        // (we verify the base64 string, not the decoded bytes, to prevent canonicalization attacks)
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, public_key.as_ref());

        peer_public_key
            .verify(payload_b64.as_bytes(), &sig_bytes)
            .map_err(|_| LicenseError::InvalidSignature)?;

        // Parse JSON payload
        let license: License = serde_json::from_slice(&payload_bytes)
            .map_err(|e| LicenseError::InvalidPayload(e.to_string()))?;

        // Validate version
        if license.version != 1 {
            return Err(LicenseError::UnsupportedVersion(license.version));
        }

        // A trial must describe a finite, well-formed interval. Validate only
        // trials to preserve existing commercial and perpetual entitlements.
        // Expired but structurally valid trials remain verifiable: the manager
        // reports Expired, and consumers can apply their existing grace policy.
        if license.license_type == crate::types::LicenseType::Trial {
            let invalid = |message: &str| LicenseError::InvalidPayload(message.to_owned());
            let issued = chrono::DateTime::parse_from_rfc3339(&license.issued_at)
                .map_err(|_| invalid("trial issued_at must be an RFC 3339 timestamp"))?;
            let expires = license
                .expires_at
                .as_deref()
                .ok_or_else(|| invalid("trial expires_at is required"))?;
            let expires = chrono::DateTime::parse_from_rfc3339(expires)
                .map_err(|_| invalid("trial expires_at must be an RFC 3339 timestamp"))?;
            if expires <= issued {
                return Err(invalid("trial expires_at must be after issued_at"));
            }
        }

        Ok(license)
    }

    /// Read and verify a license file from disk.
    pub fn verify_file(
        path: &std::path::Path,
        public_key: &[u8; 32],
    ) -> Result<License, LicenseError> {
        let data = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                LicenseError::FileNotFound(path.display().to_string())
            } else {
                LicenseError::Io(e)
            }
        })?;
        Self::verify(&data, public_key)
    }
}
