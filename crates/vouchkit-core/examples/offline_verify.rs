//! Verify a stored license without the activation client or server.

use std::{
    env,
    error::Error,
    fs, io,
    time::{SystemTime, UNIX_EPOCH},
};
use vouchkit_core::{Verifier, VerifyOptions, VerifyOutcome, protocol::parse_master_key};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [public_key, license, product] = args.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: offline_verify master.pub license.vouch product",
        )
        .into());
    };
    let product = product
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "product must be UTF-8"))?;
    let key = parse_master_key(&fs::read_to_string(public_key)?)?;
    let token = fs::read_to_string(license)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let verifier = Verifier::with_public_keys(&[key], None);
    let outcome = verifier.verify(&token, &VerifyOptions::new(product, (1, 0, 0), now))?;
    match outcome {
        VerifyOutcome::NeedsActivation(_) => println!("Purchase requires activation"),
        outcome => {
            println!("{:?}", outcome.state());
            if let Some(license) = outcome.license() {
                println!(
                    "Feature 1000 enabled = {}",
                    license.payload().features.contains(1000)
                );
            }
        }
    }
    Ok(())
}
