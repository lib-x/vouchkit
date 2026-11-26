#![no_main]

use libfuzzer_sys::fuzz_target;
use vouchkit_core::protocol::{ActivateRequest, DeactivateRequest, MAX_JSON_BYTES, RenewRequest};

fuzz_target!(|data: &[u8]| {
    if data.len() <= MAX_JSON_BYTES {
        if let Ok(req) = serde_json::from_slice::<ActivateRequest>(data) {
            let _ = req.verify_proof([0; 16]);
        }
        if let Ok(req) = serde_json::from_slice::<RenewRequest>(data) {
            let _ = req.verify_proof([0; 16], [0; 32].into());
        }
        if let Ok(req) = serde_json::from_slice::<DeactivateRequest>(data) {
            let _ = req.verify_proof([0; 16]);
        }
    }
});
