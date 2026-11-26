//! Adapt an Ed25519- or P-256-capable USB dongle or HSM through a key handle or vendor session.

use std::error::Error;

use vouchkit_core::{
    DeviceKeyError, DeviceProver, PublicKey, SigningAlgorithm, SigningProvider, SoftwareSigningKey,
};

struct DeviceSigner<F> {
    public_key: PublicKey,
    sign_with_device: F,
}

impl<F> DeviceProver for DeviceSigner<F>
where
    F: Fn(&[u8]) -> Result<[u8; 64], DeviceKeyError>,
{
    fn public(&self) -> PublicKey {
        self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        (self.sign_with_device)(message)
    }
}

fn sign_with(prover: &dyn DeviceProver) -> Result<(), DeviceKeyError> {
    let proof = prover.sign(b"vouchkit hardware adapter example")?;
    println!(
        "Received {} proof bytes for key {:?}",
        proof.len(),
        prover.public()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // The demo stays runnable on machines with no hardware. A real integration
    // supplies the registered public key and a callback to its vendor session.
    let demo = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &[7; 32])?;
    let device = DeviceSigner {
        public_key: demo.public_key(),
        sign_with_device: |message: &[u8]| {
            demo.try_sign(message)
                .map_err(|_| DeviceKeyError::SigningFailed)
        },
    };
    sign_with(&device)?;
    Ok(())
}
