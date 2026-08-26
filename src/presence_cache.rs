//! Monotonic, applet-scoped physical-presence cache.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct TouchCache {
    touched: BTreeMap<&'static str, Instant>,
}

impl TouchCache {
    pub(crate) fn record(&mut self, application: &'static str, now: Instant) {
        self.touched.insert(application, now);
    }

    pub(crate) fn is_valid(
        &self,
        application: &'static str,
        timeout: Duration,
        now: Instant,
    ) -> bool {
        self.touched.get(application).is_some_and(|touched| {
            now.checked_duration_since(*touched)
                .is_some_and(|elapsed| elapsed < timeout)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_touch_expires_at_fifteen_seconds() {
        let started = Instant::now();
        let mut cache = TouchCache::default();
        cache.record("piv", started);

        assert!(cache.is_valid(
            "piv",
            Duration::from_secs(15),
            started + Duration::from_millis(14_999)
        ));
        assert!(!cache.is_valid(
            "piv",
            Duration::from_secs(15),
            started + Duration::from_secs(15)
        ));
    }

    #[test]
    fn touch_cache_is_scoped_to_the_requesting_applet() {
        let now = Instant::now();
        let mut cache = TouchCache::default();
        cache.record("fido", now);

        assert!(cache.is_valid("fido", Duration::from_secs(15), now));
        assert!(!cache.is_valid("piv", Duration::from_secs(15), now));
    }
}
