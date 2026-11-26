use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Id, LicenseError, random_bytes};

const TAG_COUNT: usize = 8;
const TAG_LEN: usize = 4;
const TAG_MASTER_CONTEXT: &str = "vouchkit-tag-master-v1";
const TAG_SLOT_CONTEXT: &str = "vouchkit-tag-slot-v1";
const FEATURE_CONTEXT: &str = "vouchkit-feature-v1";
const ASSET_HEADER: &[u8; 8] = b"VKASSET1";
const ASSET_NONCE_LEN: usize = 24;
const AUTH_TAG_LEN: usize = 16;

/// One build-specific slot and its keyed hash material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TagSlot {
    /// Zero-based slot number.
    pub index: u8,
    /// Slot-specific derived key.
    pub key: [u8; 32],
}

impl std::fmt::Debug for TagSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TagSlot")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// The subset of tag slots verified by one application build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagProfile {
    slots: &'static [TagSlot],
}

impl TagProfile {
    /// Defines the build's subset. Validation requires two or more distinct slots.
    pub const fn new(slots: &'static [TagSlot]) -> Self {
        Self { slots }
    }

    /// Checks all configured slots against the signed values.
    ///
    /// # Errors
    ///
    /// Returns [LicenseError::TagMismatch] for absent, inconsistent or invalid tags.
    pub fn check(
        &self,
        entitlement_id: &Id,
        product: &str,
        tags: Option<&[[u8; TAG_LEN]; TAG_COUNT]>,
    ) -> Result<(), LicenseError> {
        let tags = tags.ok_or(LicenseError::TagMismatch)?;
        if !(2..=TAG_COUNT).contains(&self.slots.len()) {
            return Err(LicenseError::TagMismatch);
        }
        let mut seen = 0u8;
        let mut valid = subtle::Choice::from(1);
        for slot in self.slots {
            let bit = 1u8
                .checked_shl(u32::from(slot.index))
                .ok_or(LicenseError::TagMismatch)?;
            if seen & bit != 0 {
                return Err(LicenseError::TagMismatch);
            }
            seen |= bit;
            let tag = tags
                .get(usize::from(slot.index))
                .ok_or(LicenseError::TagMismatch)?;
            valid &= tag.ct_eq(&tag_hash(&slot.key, entitlement_id, product));
        }
        if valid.into() {
            Ok(())
        } else {
            Err(LicenseError::TagMismatch)
        }
    }
}

fn key_for_slot(tag_master: &[u8; 32], index: u8) -> [u8; 32] {
    let mut material = Zeroizing::new([0u8; 33]);
    let (master, slot) = material.split_at_mut(32);
    master.copy_from_slice(tag_master);
    slot.fill(index);
    blake3::derive_key(TAG_SLOT_CONTEXT, material.as_ref())
}

fn tag_hash(key: &[u8; 32], entitlement_id: &Id, product: &str) -> [u8; TAG_LEN] {
    let digest = blake3::Hasher::new_keyed(key)
        .update(entitlement_id)
        .update(product.as_bytes())
        .finalize();
    let mut tag = [0; TAG_LEN];
    for (out, input) in tag.iter_mut().zip(digest.as_bytes()) {
        *out = *input;
    }
    tag
}

/// Derives the key for one tag slot from the offline author seed.
///
/// # Errors
///
/// Returns [LicenseError::Malformed] if the slot does not exist.
pub fn derive_tag_slot(seed: &[u8; 32], index: u8) -> Result<[u8; 32], LicenseError> {
    if usize::from(index) >= TAG_COUNT {
        return Err(LicenseError::Malformed);
    }
    let tag_master = Zeroizing::new(blake3::derive_key(TAG_MASTER_CONTEXT, seed));
    Ok(key_for_slot(&tag_master, index))
}

/// Derives all signed tag values from the offline author seed.
pub fn derive_tags(
    seed: &[u8; 32],
    entitlement_id: &Id,
    product: &str,
) -> [[u8; TAG_LEN]; TAG_COUNT] {
    let tag_master = Zeroizing::new(blake3::derive_key(TAG_MASTER_CONTEXT, seed));
    std::array::from_fn(|index| {
        let key = Zeroizing::new(key_for_slot(&tag_master, index as u8));
        tag_hash(&key, entitlement_id, product)
    })
}

/// Derives a product and slot-specific resource key from the offline author seed.
pub fn derive_feature_key(seed: &[u8; 32], product: &str, feature: u16) -> [u8; 32] {
    let mut material = Zeroizing::new(Vec::new());
    material.extend_from_slice(seed);
    material.extend_from_slice(product.as_bytes());
    material.extend_from_slice(&feature.to_be_bytes());
    blake3::derive_key(FEATURE_CONTEXT, &material)
}

/// Encrypts and authenticates a resource using a randomly generated nonce.
///
/// # Errors
///
/// Returns an error if secure randomness or encryption is unavailable.
pub fn asset_seal(key: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>, LicenseError> {
    let nonce: [u8; ASSET_NONCE_LEN] = random_bytes()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: bytes,
                aad: ASSET_HEADER,
            },
        )
        .map_err(|_| LicenseError::Malformed)?;
    Ok([ASSET_HEADER.as_slice(), &nonce, &ciphertext].concat())
}

/// Decrypts a resource obtained through an authorized feature grant.
///
/// # Errors
///
/// Returns an error if the container or its authentication tag is invalid.
pub fn asset_open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, LicenseError> {
    let rest = sealed
        .strip_prefix(ASSET_HEADER)
        .ok_or(LicenseError::Malformed)?;
    let (nonce, ciphertext) = rest
        .split_at_checked(ASSET_NONCE_LEN)
        .ok_or(LicenseError::Malformed)?;
    if ciphertext.len() < AUTH_TAG_LEN {
        return Err(LicenseError::Malformed);
    }
    let nonce: [u8; ASSET_NONCE_LEN] = nonce.try_into().map_err(|_| LicenseError::Malformed)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: ASSET_HEADER,
            },
        )
        .map_err(|_| LicenseError::BadSignature)
}

/// Compile-time support for [`crate::embed_pubkeys`].
#[doc(hidden)]
pub const fn key_fragment(id: u8, key: &[u8; 32]) -> [u8; 32] {
    let mut fragment = [0; 32];
    let mut index = 0;
    let mut state = 0xcbf2_9ce4_8422_2325u64 ^ id as u64;
    while index < 32 {
        state ^= key[index] as u64;
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
        fragment[index] = (state >> 32) as u8;
        index += 1;
    }
    fragment
}

#[doc(hidden)]
pub const fn xor_key_fragment(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0; 32];
    let mut index = 0;
    while index < 32 {
        combined[index] = a[index] ^ b[index];
        index += 1;
    }
    combined
}

/// Reconstructs trusted public keys from separately stored XOR fragments.
///
/// Use `embed_pubkeys![(1, PUBLIC_KEY), (2, NEXT_PUBLIC_KEY)]` to obtain
/// an array of the entries accepted by [crate::Verifier::new].
#[macro_export]
macro_rules! embed_pubkeys {
    ($(($id:expr, $key:expr)),* $(,)?) => {
        [$({
            const ID: u8 = $id;
            const KEY: [u8; 32] = $key;
            static LEFT: [u8; 32] = $crate::__key_fragment(ID, &KEY);
            static RIGHT: [u8; 32] = $crate::__xor_key_fragment(&LEFT, &KEY);
            (ID, $crate::__xor_key_fragment(::std::hint::black_box(&LEFT), ::std::hint::black_box(&RIGHT)))
        }),*]
    };
}
