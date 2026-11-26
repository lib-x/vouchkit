use std::error::Error;

use thiserror::Error;
use vouchkit_core::{AppVersion, Id, PublicKey};

/// An activation backend failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Underlying storage failed. The source is available for operator diagnostics.
    #[error("activation state operation failed")]
    Backend(#[source] Box<dyn Error + Send + Sync>),
    /// A backend was asked to write in a read-only transaction.
    #[error("activation transaction is read-only")]
    ReadOnly,
    /// Storage state or behavior violated the activation transaction contract.
    #[error("{0}")]
    InvalidState(&'static str),
}

impl StoreError {
    /// Wraps an underlying storage error without adding it to the HTTP response.
    pub fn backend(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Backend(Box::new(error))
    }
}

/// Isolation and write access required by an activation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionMode {
    /// Read one consistent, committed snapshot.
    Read,
    /// Execute an atomic, serializable update with read-your-writes behavior.
    Write,
}

/// The engine's decision after applying an activation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionControl {
    /// Publish all transaction writes atomically before returning success.
    Commit,
    /// Discard all transaction writes.
    Rollback,
}

/// Stable identity of an activation seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceIdentity {
    /// Purchase identifier.
    pub entitlement_id: Id,
    /// Canonical, algorithm-specific device public key.
    pub public_key: PublicKey,
}

/// User-supplied metadata attached to an active registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    /// Application version last reported during activation.
    pub app_version: AppVersion,
    /// Optional device hint for diagnostics.
    pub device_hint: Option<Id>,
}

/// The last accepted signed revocation list and its authenticated sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCrl {
    /// Sequence committed together with the signed bytes.
    pub sequence: u64,
    /// The exact author-signed bytes.
    pub bytes: Vec<u8>,
}

/// Transactional state required by the activation policy engine.
///
/// Backends must share authoritative state across instances serving the same
/// purchases. Production deployments must durably commit signed purchase credentials,
/// seat registrations, issued lease IDs, used nonces, clock state and CRLs.
/// Retry a failed request after an aborted transaction using a fresh transaction.
/// Use a backup and restore policy that accounts for rollback of security state.
pub trait ActivationStore: Send + Sync {
    /// Executes the callback once in a consistent transaction.
    ///
    /// Concurrent write transactions must be serializable, including seat count
    /// predicates and nonce uniqueness. A callback may sign a lease and must
    /// never be retried internally. After an accepted commit, later operations
    /// must observe its state. A rollback or interrupted callback discards all
    /// writes. Write operations invoked in a read transaction must be rejected.
    ///
    /// # Errors
    ///
    /// Returns a backend failure if beginning, committing or rolling back the
    /// transaction fails. An unconfirmed commit must surface as an error.
    fn transaction(
        &self,
        mode: TransactionMode,
        operation: &mut dyn FnMut(&mut dyn ActivationTransaction) -> TransactionControl,
    ) -> Result<(), StoreError>;
}

impl<T: ActivationStore + ?Sized> ActivationStore for Box<T> {
    fn transaction(
        &self,
        mode: TransactionMode,
        operation: &mut dyn FnMut(&mut dyn ActivationTransaction) -> TransactionControl,
    ) -> Result<(), StoreError> {
        self.as_ref().transaction(mode, operation)
    }
}

/// Operations on the consistent state isolated by the surrounding transaction.
///
/// All methods return a storage error when the backend cannot perform the
/// operation. Mutations participate in the surrounding commit or rollback.
pub trait ActivationTransaction {
    /// Gets the largest accepted Unix timestamp, or zero on initial state.
    fn last_seen_time(&self) -> Result<u64, StoreError>;
    /// Records the larger timestamp already checked by the engine.
    fn set_last_seen_time(&mut self, time: u64) -> Result<(), StoreError>;
    /// Gets the latest CRL revision, or `None` when no CRL is stored.
    ///
    /// Backends can override this method to read only the sequence. Its result
    /// must agree with the signed record returned by this transaction.
    fn crl_sequence(&self) -> Result<Option<u64>, StoreError> {
        Ok(self.crl()?.map(|crl| crl.sequence))
    }
    /// Gets the sequence and signed CRL together from the current snapshot.
    fn crl(&self) -> Result<Option<StoredCrl>, StoreError>;
    /// Replaces the signed CRL and its sequence, after validation by the engine.
    fn set_crl(&mut self, sequence: u64, bytes: &[u8]) -> Result<(), StoreError>;

    /// Records a request nonce and returns whether it had not been seen before.
    fn insert_nonce(&mut self, device: DeviceIdentity, nonce: Id) -> Result<bool, StoreError>;
    /// Retrieves the exact master-signed entitlement bound to a purchase.
    fn entitlement(&self, id: Id) -> Result<Option<Vec<u8>>, StoreError>;
    /// Records the original entitlement if the purchase has no committed token.
    fn insert_entitlement(&mut self, id: Id, token: &[u8]) -> Result<(), StoreError>;
    /// Retrieves an active seat registration, if this device already holds one.
    fn registration(&self, device: DeviceIdentity) -> Result<Option<Registration>, StoreError>;
    /// Counts the purchase's active seats in the current transaction.
    fn active_devices(&self, entitlement_id: Id) -> Result<u64, StoreError>;
    /// Creates or reenables the seat and records the current activation metadata.
    fn activate(
        &mut self,
        device: DeviceIdentity,
        registration: Registration,
        now: u64,
    ) -> Result<(), StoreError>;
    /// Updates the last-seen timestamp of an active registration.
    fn touch(&mut self, device: DeviceIdentity, now: u64) -> Result<(), StoreError>;
    /// Records a new lease ID for a seat through the given grace deadline.
    ///
    /// Rejects duplicate IDs. Backends may prune expired lease IDs for the device
    /// using the current time as the threshold.
    fn register_lease(
        &mut self,
        device: DeviceIdentity,
        lease_id: Id,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError>;
    /// Checks whether this exact lease belongs to the current registration.
    fn has_lease(&self, device: DeviceIdentity, lease_id: Id) -> Result<bool, StoreError>;
    /// Releases the seat and removes all its earlier lease registrations.
    fn deactivate(&mut self, device: DeviceIdentity, now: u64) -> Result<(), StoreError>;
}
