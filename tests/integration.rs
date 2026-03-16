//! Integration tests for trident-license.

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use trident_license::{
    License, LicenseCustomer, LicenseError, LicenseManager, LicenseStatus, LicenseType,
    LicenseVerifier,
};

/// Generate a test Ed25519 keypair, returning (keypair, public_key_bytes).
fn generate_test_keypair() -> (Ed25519KeyPair, [u8; 32]) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    (keypair, public_key)
}

/// Sign a JSON payload and return the license file content.
fn sign_payload(keypair: &Ed25519KeyPair, payload_json: &str) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    let payload_b64 = engine.encode(payload_json.as_bytes());
    let sig = keypair.sign(payload_b64.as_bytes());
    let sig_b64 = engine.encode(sig.as_ref());
    format!("{payload_b64}.{sig_b64}")
}

fn commercial_license_json(expires: &str) -> String {
    format!(
        r#"{{
        "version": 1,
        "product": "trident-cache",
        "license_id": "lic-001",
        "customer": {{ "name": "Acme Corp", "email": "admin@acme.com" }},
        "license_type": "commercial",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "{expires}"
    }}"#
    )
}

fn trial_license_json(expires: &str) -> String {
    format!(
        r#"{{
        "version": 1,
        "product": "trident-cache",
        "license_id": "trial-001",
        "customer": {{ "name": "Trial User", "email": "trial@example.com" }},
        "license_type": "trial",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "{expires}"
    }}"#
    )
}

fn perpetual_license_json() -> String {
    r#"{
        "version": 1,
        "product": "trident-cache",
        "license_id": "perp-001",
        "customer": { "name": "Enterprise", "email": "ent@example.com" },
        "license_type": "perpetual",
        "issued_at": "2026-01-01T00:00:00Z"
    }"#
    .to_string()
}

// 1. Roundtrip sign/verify
#[test]
fn test_roundtrip_sign_verify() {
    let (keypair, public_key) = generate_test_keypair();
    let json = commercial_license_json("2099-12-31T23:59:59Z");
    let data = sign_payload(&keypair, &json);

    let license = LicenseVerifier::verify(&data, &public_key).unwrap();
    assert_eq!(license.version, 1);
    assert_eq!(license.license_id, "lic-001");
    assert_eq!(license.product, "trident-cache");
    assert_eq!(license.customer.name, "Acme Corp");
    assert_eq!(license.customer.email, "admin@acme.com");
    assert_eq!(license.license_type, LicenseType::Commercial);
}

// 2. Tamper detection
#[test]
fn test_tamper_detection() {
    let (keypair, public_key) = generate_test_keypair();
    let json = commercial_license_json("2099-12-31T23:59:59Z");
    let data = sign_payload(&keypair, &json);

    // Swap out the payload but keep the original signature
    let (_, sig) = data.rsplit_once('.').unwrap();
    let engine = base64::engine::general_purpose::STANDARD;
    let tampered = engine.encode(b"{\"version\":1,\"license_id\":\"hacked\",\"customer\":{\"name\":\"X\",\"email\":\"x@x.com\"},\"license_type\":\"perpetual\",\"issued_at\":\"2026-01-01T00:00:00Z\"}");
    let tampered_data = format!("{tampered}.{sig}");

    let err = LicenseVerifier::verify(&tampered_data, &public_key).unwrap_err();
    assert!(matches!(err, LicenseError::InvalidSignature));
}

// 3. Wrong key rejection
#[test]
fn test_wrong_key_rejection() {
    let (keypair_a, _) = generate_test_keypair();
    let (_, public_key_b) = generate_test_keypair();
    let json = commercial_license_json("2099-12-31T23:59:59Z");
    let data = sign_payload(&keypair_a, &json);

    let err = LicenseVerifier::verify(&data, &public_key_b).unwrap_err();
    assert!(matches!(err, LicenseError::InvalidSignature));
}

// 4. Malformed file
#[test]
fn test_malformed_no_dot() {
    let err = LicenseVerifier::verify("nodothere", &[0u8; 32]).unwrap_err();
    assert!(matches!(err, LicenseError::MalformedFile));
}

#[test]
fn test_malformed_empty_parts() {
    let err = LicenseVerifier::verify(".signature", &[0u8; 32]).unwrap_err();
    assert!(matches!(err, LicenseError::MalformedFile));

    let err = LicenseVerifier::verify("payload.", &[0u8; 32]).unwrap_err();
    assert!(matches!(err, LicenseError::MalformedFile));
}

#[test]
fn test_invalid_base64() {
    let err = LicenseVerifier::verify("!!!.!!!", &[0u8; 32]).unwrap_err();
    assert!(matches!(err, LicenseError::InvalidBase64(_)));
}

// 5. Unsupported version
#[test]
fn test_unsupported_version() {
    let (keypair, public_key) = generate_test_keypair();
    let json = r#"{
        "version": 99,
        "license_id": "x",
        "customer": { "name": "X", "email": "x@x.com" },
        "license_type": "commercial",
        "issued_at": "2026-01-01T00:00:00Z"
    }"#;
    let data = sign_payload(&keypair, json);

    let err = LicenseVerifier::verify(&data, &public_key).unwrap_err();
    assert!(matches!(err, LicenseError::UnsupportedVersion(99)));
}

// 6. Expiry checks
#[test]
fn test_expired_license_status() {
    // Expired commercial license — tested via file in test_expired_license_via_file
    let (_, public_key) = generate_test_keypair();
    let mgr = LicenseManager::unlicensed(&public_key);
    assert!(!mgr.is_licensed());
    assert_eq!(mgr.status(), LicenseStatus::NoLicense);
}

// 7. Perpetual license
#[test]
fn test_perpetual_license_via_file() {
    let (keypair, public_key) = generate_test_keypair();
    let json = perpetual_license_json();
    let data = sign_payload(&keypair, &json);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("license.key");
    std::fs::write(&path, &data).unwrap();

    let mgr = LicenseManager::new(Some(&path), &public_key);
    assert!(mgr.is_licensed());
    assert_eq!(mgr.status(), LicenseStatus::Valid);
    assert_eq!(mgr.header_value(), None);
}

// 8. Trial license
#[test]
fn test_trial_license_active() {
    let (keypair, public_key) = generate_test_keypair();
    let json = trial_license_json("2099-12-31T23:59:59Z");
    let data = sign_payload(&keypair, &json);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("license.key");
    std::fs::write(&path, &data).unwrap();

    let mgr = LicenseManager::new(Some(&path), &public_key);
    assert!(mgr.is_licensed());
    assert_eq!(mgr.status(), LicenseStatus::Trial);
    assert_eq!(mgr.header_value(), Some("trial"));
}

// 9. Product field backward compat
#[test]
fn test_product_field_backward_compat() {
    let (keypair, public_key) = generate_test_keypair();
    // License JSON without `product` field — should default to "trident-cache"
    let json = r#"{
        "version": 1,
        "license_id": "old-001",
        "customer": { "name": "Old", "email": "old@example.com" },
        "license_type": "commercial",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z"
    }"#;
    let data = sign_payload(&keypair, json);

    let license = LicenseVerifier::verify(&data, &public_key).unwrap();
    assert_eq!(license.product, "trident-cache");
}

// 10. LicenseManager fast path
#[test]
fn test_manager_fast_path() {
    let (keypair, public_key) = generate_test_keypair();
    let json = commercial_license_json("2099-12-31T23:59:59Z");
    let data = sign_payload(&keypair, &json);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("license.key");
    std::fs::write(&path, &data).unwrap();

    let mgr = LicenseManager::new(Some(&path), &public_key);
    assert!(mgr.is_licensed());
    assert_eq!(mgr.status(), LicenseStatus::Valid);

    // No path → unlicensed
    let mgr2 = LicenseManager::new(None, &public_key);
    assert!(!mgr2.is_licensed());
    assert_eq!(mgr2.status(), LicenseStatus::NoLicense);

    // Missing file → invalid
    let mgr3 = LicenseManager::new(Some(std::path::Path::new("/nonexistent.key")), &public_key);
    assert!(!mgr3.is_licensed());
    assert_eq!(mgr3.status(), LicenseStatus::Invalid);
}

// 11. LicenseManager reload
#[test]
fn test_manager_reload() {
    let (keypair, public_key) = generate_test_keypair();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("license.key");

    // Start unlicensed
    let mgr = LicenseManager::new(None, &public_key);
    assert!(!mgr.is_licensed());

    // Write a valid license and reload
    let json = commercial_license_json("2099-12-31T23:59:59Z");
    let data = sign_payload(&keypair, &json);
    std::fs::write(&path, &data).unwrap();

    mgr.reload(&path).unwrap();
    assert!(mgr.is_licensed());
    assert_eq!(mgr.status(), LicenseStatus::Valid);
}

// 12. File I/O — verify_file
#[test]
fn test_verify_file_missing() {
    let (_, public_key) = generate_test_keypair();
    let err = LicenseVerifier::verify_file(
        std::path::Path::new("/nonexistent/license.key"),
        &public_key,
    )
    .unwrap_err();
    assert!(matches!(err, LicenseError::FileNotFound(_)));
}

#[test]
fn test_verify_file_valid() {
    let (keypair, public_key) = generate_test_keypair();
    let json = commercial_license_json("2099-12-31T23:59:59Z");
    let data = sign_payload(&keypair, &json);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("license.key");
    std::fs::write(&path, &data).unwrap();

    let license = LicenseVerifier::verify_file(&path, &public_key).unwrap();
    assert_eq!(license.license_id, "lic-001");
}

#[test]
fn test_verify_file_corrupted() {
    let (_, public_key) = generate_test_keypair();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("license.key");
    std::fs::write(&path, "corrupted-garbage-data").unwrap();

    let err = LicenseVerifier::verify_file(&path, &public_key).unwrap_err();
    assert!(matches!(err, LicenseError::MalformedFile));
}

// Expired license via manager (file-based)
#[test]
fn test_expired_license_via_file() {
    let (keypair, public_key) = generate_test_keypair();
    let json = commercial_license_json("2020-01-01T00:00:00Z");
    let data = sign_payload(&keypair, &json);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("license.key");
    std::fs::write(&path, &data).unwrap();

    let mgr = LicenseManager::new(Some(&path), &public_key);
    assert!(!mgr.is_licensed());
    assert_eq!(mgr.status(), LicenseStatus::Expired);
    assert_eq!(mgr.header_value(), Some("expired"));
}

// Whitespace handling
#[test]
fn test_verify_with_trailing_whitespace() {
    let (keypair, public_key) = generate_test_keypair();
    let json = commercial_license_json("2099-12-31T23:59:59Z");
    let data = format!("  {}  \n", sign_payload(&keypair, &json));

    let license = LicenseVerifier::verify(&data, &public_key).unwrap();
    assert_eq!(license.license_id, "lic-001");
}
