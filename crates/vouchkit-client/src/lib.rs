//! Activation, renewable leases and device key storage for offline-first licensing.

mod device;
mod renewer;
mod state;
mod transport;

pub use device::{DeviceKey, DeviceKeyStore, DeviceStorageError};
pub use renewer::{Action, ClientError, Deactivation, Renewal, Renewer};
pub use state::{FileStateStore, MemoryStateStore, StateFileError};
#[cfg(feature = "reqwest")]
pub use transport::ReqwestTransport;
pub use transport::{Transport, TransportError};
