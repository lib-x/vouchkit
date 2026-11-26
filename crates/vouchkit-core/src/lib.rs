#![doc = include_str!("../README.md")]

mod codec;
mod features;
mod hardening;
mod model;
pub mod protocol;
mod verifier;
mod wire;

pub use codec::{MAX_TOKEN_TEXT, decode_token, encode_license_file, encode_token};
pub use features::{FeatureSlots, MAX_FEATURE_RANGES};
pub use hardening::{
    TagProfile, TagSlot, asset_open, asset_seal, derive_feature_key, derive_tag_slot, derive_tags,
};
pub use model::{
    AppVersion, Class, Crl, DelegationCert, DeviceKeyError, DeviceProver, EntitlementInfo, Id,
    LicenseError, LicensePayload, LicenseState, StateStore, VerifiedLicense, VerifyOptions,
    VerifyOutcome, check_clock, check_clock_with_skew, random_bytes, validate_product,
};
pub use verifier::Verifier;
pub use wire::{
    Ed25519Signer, InspectedLicense, SignedLicense, SigningError, SigningKey, inspect_license,
    sign_crl, sign_delegation, sign_lease, sign_master,
};

#[doc(hidden)]
pub use hardening::{key_fragment as __key_fragment, xor_key_fragment as __xor_key_fragment};
