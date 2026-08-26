//! Applet-local physical-presence policy and cache state.

use crate::{PresenceAuthorization, UserPresencePolicy};
use std::time::Instant;

/// Common transient presence facade embedded in each applet that needs touch.
///
/// The transport owns the physical sensor and blink behavior. This value owns
/// only applet policy state, so cached authorization cannot cross applets and
/// is never included in persistent state.
#[derive(Debug, Default)]
pub(crate) struct PresenceClient {
    last_touch: Option<Instant>,
}

impl PresenceClient {
    pub(crate) fn authorize(
        &mut self,
        policy: UserPresencePolicy,
        authorization: PresenceAuthorization,
    ) -> bool {
        self.authorize_at(policy, authorization, Instant::now())
    }

    fn authorize_at(
        &mut self,
        policy: UserPresencePolicy,
        authorization: PresenceAuthorization,
        now: Instant,
    ) -> bool {
        if authorization == PresenceAuthorization::Granted {
            self.last_touch = Some(now);
            return true;
        }
        match policy {
            UserPresencePolicy::Always => false,
            UserPresencePolicy::Cached(timeout) => self.last_touch.is_some_and(|touched| {
                now.checked_duration_since(touched)
                    .is_some_and(|elapsed| elapsed < timeout)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cached_presence_is_local_and_expires_without_extending_on_a_hit() {
        let started = Instant::now();
        let timeout = Duration::from_secs(15);
        let mut first = PresenceClient::default();
        let mut second = PresenceClient::default();

        assert!(!first.authorize_at(
            UserPresencePolicy::Cached(timeout),
            PresenceAuthorization::Absent,
            started,
        ));
        assert!(first.authorize_at(
            UserPresencePolicy::Always,
            PresenceAuthorization::Granted,
            started,
        ));
        assert!(first.authorize_at(
            UserPresencePolicy::Cached(timeout),
            PresenceAuthorization::Absent,
            started + Duration::from_millis(14_999),
        ));
        assert!(!first.authorize_at(
            UserPresencePolicy::Cached(timeout),
            PresenceAuthorization::Absent,
            started + timeout,
        ));
        assert!(!second.authorize_at(
            UserPresencePolicy::Cached(timeout),
            PresenceAuthorization::Absent,
            started,
        ));
    }

    #[test]
    fn always_never_uses_the_cache_but_a_new_touch_refreshes_it() {
        let started = Instant::now();
        let mut client = PresenceClient::default();
        assert!(client.authorize_at(
            UserPresencePolicy::Always,
            PresenceAuthorization::Granted,
            started,
        ));
        assert!(!client.authorize_at(
            UserPresencePolicy::Always,
            PresenceAuthorization::Absent,
            started,
        ));
        assert!(client.authorize_at(
            UserPresencePolicy::Cached(Duration::from_secs(15)),
            PresenceAuthorization::Absent,
            started,
        ));
    }
}
