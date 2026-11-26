use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use vouchkit_core::Id;

use crate::ServerError;

const WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED: u32 = 65_536;

#[derive(Debug)]
pub(crate) struct Limits {
    ip: Mutex<Window<IpAddr>>,
    entitlement: Mutex<Window<Id>>,
}

impl Limits {
    pub(crate) fn new(ip: u32, entitlement: u32, global: u32) -> Result<Self, ServerError> {
        if ip == 0 || entitlement == 0 || !(1..=MAX_TRACKED).contains(&global) {
            return Err(ServerError::Config("invalid request rate limits"));
        }
        Ok(Self {
            ip: Mutex::new(Window::new(ip, global)),
            entitlement: Mutex::new(Window::new(entitlement, global)),
        })
    }

    pub(crate) fn check_ip(&self, ip: IpAddr) -> Result<(), ServerError> {
        lock(&self.ip)?.check(ip.to_canonical(), Instant::now())
    }

    pub(crate) fn check_entitlement(&self, id: Id) -> Result<(), ServerError> {
        lock(&self.entitlement)?.check(id, Instant::now())
    }
}

pub(crate) fn lock<T>(lock: &Mutex<T>) -> Result<MutexGuard<'_, T>, ServerError> {
    lock.lock().map_err(|_| ServerError::Poisoned)
}

#[derive(Debug)]
struct Window<K> {
    reset_at: Instant,
    counts: HashMap<K, u32>,
    total: u32,
    per_key: u32,
    global: u32,
}

impl<K: Eq + Hash> Window<K> {
    fn new(per_key: u32, global: u32) -> Self {
        Self {
            reset_at: Instant::now() + WINDOW,
            counts: HashMap::new(),
            total: 0,
            per_key,
            global,
        }
    }

    fn check(&mut self, key: K, now: Instant) -> Result<(), ServerError> {
        if now >= self.reset_at {
            self.reset_at = now + WINDOW;
            self.total = 0;
            self.counts.clear();
        }
        if self.total >= self.global {
            return Err(ServerError::RateLimited);
        }
        let count = self.counts.entry(key).or_default();
        if *count >= self.per_key {
            return Err(ServerError::RateLimited);
        }
        *count += 1;
        self.total += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn individual_and_global_limits_reset_together() -> Result<(), ServerError> {
        let mut limit = Window::new(1, 2);
        let now = Instant::now();
        limit.check(1, now)?;
        assert!(matches!(limit.check(1, now), Err(ServerError::RateLimited)));
        limit.check(2, now)?;
        assert!(matches!(limit.check(3, now), Err(ServerError::RateLimited)));
        limit.check(1, now + WINDOW)?;
        Ok(())
    }
}
