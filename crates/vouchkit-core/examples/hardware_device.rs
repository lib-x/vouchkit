//! Adapt an Ed25519-capable USB dongle or HSM through a key handle or vendor session.

use std::error::Error;

use vouchkit_core::{DeviceKeyError, DeviceProver, SigningKey};

struct DeviceSigner<F> {
    public_key: [u8; 32],
    sign_with_device: F,
}

impl<F> DeviceProver for DeviceSigner<F>
where
    F: Fn(&[u8]) -> Result<[u8; 64], DeviceKeyError>,
{
    fn public(&self) -> [u8; 32] {
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
    let demo = SigningKey::from_seed(&[7; 32]);
    let device = DeviceSigner {
        public_key: demo.public(),
        sign_with_device: |message: &[u8]| Ok(demo.sign(message)),
    };
    sign_with(&device)?;
    Ok(())
}
