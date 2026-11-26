use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    sync::Mutex,
};

use vouchkit_core::Id;
use zeroize::Zeroizing;

use crate::{
    ActivationStore, ActivationTransaction, DeviceIdentity, Registration, StoreError, StoredCrl,
    TransactionControl, TransactionMode,
};

/// A process-local activation store for tests and ephemeral deployments.
///
/// The state remains consistent across concurrent requests sharing this value.
/// Restarting drops every registration, nonce, clock value, and stored CRL.
#[derive(Default)]
pub struct MemoryActivationStore {
    state: Mutex<State>,
}

impl MemoryActivationStore {
    /// Creates an empty process-local activation store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for MemoryActivationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryActivationStore")
            .finish_non_exhaustive()
    }
}

impl ActivationStore for MemoryActivationStore {
    fn transaction(
        &self,
        mode: TransactionMode,
        operation: &mut dyn FnMut(&mut dyn ActivationTransaction) -> TransactionControl,
    ) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StoreError::InvalidState("activation mutex poisoned"))?;
        let mut transaction = MemoryTransaction {
            state: &mut state,
            mode,
            undo: Vec::new(),
        };
        if operation(&mut transaction) == TransactionControl::Commit {
            transaction.undo.clear();
        }
        Ok(())
    }
}

type UsedNonce = (DeviceIdentity, Id);

#[derive(Default)]
struct State {
    clock: u64,
    crl: Option<StoredCrl>,
    nonces: HashSet<UsedNonce>,
    entitlements: HashMap<Id, Zeroizing<Vec<u8>>>,
    seats: HashMap<DeviceIdentity, ActiveSeat>,
    leases: HashMap<Id, Lease>,
}

#[derive(Clone, Copy)]
struct ActiveSeat {
    claims: Registration,
    last_seen: u64,
}

#[derive(Clone, Copy)]
struct Lease {
    device: DeviceIdentity,
    expires: u64,
}

enum Undo {
    Clock(u64),
    Crl(Option<StoredCrl>),
    Nonce(UsedNonce),
    Entitlement(Id),
    Seat(DeviceIdentity, Option<ActiveSeat>),
    Lease(Id, Option<Lease>),
}

struct MemoryTransaction<'a> {
    state: &'a mut State,
    mode: TransactionMode,
    undo: Vec<Undo>,
}

impl MemoryTransaction<'_> {
    fn require_write(&self) -> Result<(), StoreError> {
        if self.mode == TransactionMode::Read {
            return Err(StoreError::ReadOnly);
        }
        Ok(())
    }

    fn remove_leases(&mut self, matches: impl Fn(Lease) -> bool) {
        self.state.leases.retain(|id, lease| {
            if matches(*lease) {
                self.undo.push(Undo::Lease(*id, Some(*lease)));
                false
            } else {
                true
            }
        });
    }
}

impl Drop for MemoryTransaction<'_> {
    fn drop(&mut self) {
        for undo in self.undo.drain(..).rev() {
            match undo {
                Undo::Clock(clock) => self.state.clock = clock,
                Undo::Crl(crl) => self.state.crl = crl,
                Undo::Nonce(nonce) => {
                    self.state.nonces.remove(&nonce);
                }
                Undo::Entitlement(id) => {
                    self.state.entitlements.remove(&id);
                }
                Undo::Seat(key, seat) => restore(&mut self.state.seats, key, seat),
                Undo::Lease(id, lease) => restore(&mut self.state.leases, id, lease),
            }
        }
    }
}

fn restore<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>, key: K, value: Option<V>) {
    if let Some(value) = value {
        map.insert(key, value);
    } else {
        map.remove(&key);
    }
}

impl ActivationTransaction for MemoryTransaction<'_> {
    fn last_seen_time(&self) -> Result<u64, StoreError> {
        Ok(self.state.clock)
    }

    fn set_last_seen_time(&mut self, time: u64) -> Result<(), StoreError> {
        self.require_write()?;
        self.undo
            .push(Undo::Clock(std::mem::replace(&mut self.state.clock, time)));
        Ok(())
    }

    fn crl_sequence(&self) -> Result<Option<u64>, StoreError> {
        Ok(self.state.crl.as_ref().map(|crl| crl.sequence))
    }

    fn crl(&self) -> Result<Option<StoredCrl>, StoreError> {
        Ok(self.state.crl.clone())
    }

    fn set_crl(&mut self, sequence: u64, bytes: &[u8]) -> Result<(), StoreError> {
        self.require_write()?;
        let prev = self.state.crl.replace(StoredCrl {
            sequence,
            bytes: bytes.to_owned(),
        });
        self.undo.push(Undo::Crl(prev));
        Ok(())
    }

    fn insert_nonce(&mut self, device: DeviceIdentity, nonce: Id) -> Result<bool, StoreError> {
        self.require_write()?;
        let entry = (device, nonce);
        let inserted = self.state.nonces.insert(entry);
        if inserted {
            self.undo.push(Undo::Nonce(entry));
        }
        Ok(inserted)
    }

    fn entitlement(&self, id: Id) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.state.entitlements.get(&id).map(|bytes| bytes.to_vec()))
    }

    fn insert_entitlement(&mut self, id: Id, token: &[u8]) -> Result<(), StoreError> {
        self.require_write()?;
        if let Entry::Vacant(entry) = self.state.entitlements.entry(id) {
            entry.insert(Zeroizing::new(token.to_owned()));
            self.undo.push(Undo::Entitlement(id));
        }
        Ok(())
    }

    fn registration(&self, device: DeviceIdentity) -> Result<Option<Registration>, StoreError> {
        Ok(self.state.seats.get(&device).map(|seat| seat.claims))
    }

    fn active_devices(&self, entitlement_id: Id) -> Result<u64, StoreError> {
        Ok(self
            .state
            .seats
            .keys()
            .filter(|device| device.entitlement_id == entitlement_id)
            .count() as u64)
    }

    fn activate(
        &mut self,
        device: DeviceIdentity,
        registration: Registration,
        now: u64,
    ) -> Result<(), StoreError> {
        self.require_write()?;
        let old = self.state.seats.insert(
            device,
            ActiveSeat {
                claims: registration,
                last_seen: now,
            },
        );
        self.undo.push(Undo::Seat(device, old));
        Ok(())
    }

    fn touch(&mut self, device: DeviceIdentity, now: u64) -> Result<(), StoreError> {
        self.require_write()?;
        if let Some(seat) = self.state.seats.get_mut(&device) {
            self.undo.push(Undo::Seat(device, Some(*seat)));
            seat.last_seen = now;
        }
        Ok(())
    }

    fn register_lease(
        &mut self,
        device: DeviceIdentity,
        lease_id: Id,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        self.require_write()?;
        if self.state.leases.contains_key(&lease_id) {
            return Err(StoreError::InvalidState("duplicate issued lease ID"));
        }
        self.remove_leases(|lease| lease.device == device && lease.expires <= now);
        self.state.leases.insert(
            lease_id,
            Lease {
                device,
                expires: expires_at,
            },
        );
        self.undo.push(Undo::Lease(lease_id, None));
        Ok(())
    }

    fn has_lease(&self, device: DeviceIdentity, lease_id: Id) -> Result<bool, StoreError> {
        Ok(self
            .state
            .leases
            .get(&lease_id)
            .is_some_and(|lease| lease.device == device))
    }

    fn deactivate(&mut self, device: DeviceIdentity, _now: u64) -> Result<(), StoreError> {
        self.require_write()?;
        self.undo
            .push(Undo::Seat(device, self.state.seats.remove(&device)));
        self.remove_leases(|lease| lease.device == device);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_discards_every_write_and_read_transactions_reject_mutation()
    -> Result<(), StoreError> {
        let store = MemoryActivationStore::new();
        let device = DeviceIdentity {
            entitlement_id: [1; 16],
            public_key: vouchkit_core::SigningKey::from_seed(&[3; 32])
                .public()
                .into(),
        };
        let nonce = [2; 16];
        let lease = [4; 16];
        store.transaction(TransactionMode::Write, &mut |tx| {
            tx.set_last_seen_time(100).expect("record clock");
            tx.set_crl(1, b"crl").expect("write signed CRL");
            assert!(tx.insert_nonce(device, nonce).expect("consume nonce"));
            tx.insert_entitlement(device.entitlement_id, b"token")
                .expect("store entitlement");
            tx.activate(
                device,
                Registration {
                    app_version: (1, 2, 3),
                    device_hint: None,
                },
                100,
            )
            .expect("reserve seat");
            tx.register_lease(device, lease, 200, 100)
                .expect("register lease");
            TransactionControl::Rollback
        })?;
        store.transaction(TransactionMode::Read, &mut |tx| {
            assert_eq!(tx.last_seen_time().expect("read clock"), 0);
            assert!(tx.crl().expect("read CRL").is_none());
            assert!(
                tx.entitlement(device.entitlement_id)
                    .expect("read entitlement")
                    .is_none()
            );
            assert!(
                tx.registration(device)
                    .expect("read registration")
                    .is_none()
            );
            assert!(!tx.has_lease(device, lease).expect("check lease"));
            assert!(matches!(
                tx.insert_nonce(device, nonce),
                Err(StoreError::ReadOnly)
            ));
            TransactionControl::Commit
        })?;
        store.transaction(TransactionMode::Write, &mut |tx| {
            assert!(
                tx.insert_nonce(device, nonce)
                    .expect("reuse rolled-back nonce")
            );
            TransactionControl::Commit
        })?;
        Ok(())
    }
}
