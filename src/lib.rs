//! Shared Ed25519 license verification for Trident products.
//!
//! Each product embeds its own Ed25519 public key. This crate is product-agnostic.
//!
//! ## Feature: `licensing`
//!
//! When the `licensing` feature is disabled, all license checks are bypassed
//! and `is_licensed()` always returns `true`.

pub mod manager;
pub mod types;
pub mod verifier;

pub use manager::LicenseManager;
pub use types::{License, LicenseCustomer, LicenseStatus, LicenseType};
pub use verifier::{LicenseError, LicenseVerifier};
