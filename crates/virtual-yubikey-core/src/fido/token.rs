//! CTAP PIN/UV authorization state. Secret bytes never appear in Debug output.

use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(super) const MC: u8 = 0x01;
pub(super) const GA: u8 = 0x02;
pub(super) const CM: u8 = 0x04;
pub(super) const PCMR: u8 = 0x40;

#[derive(Clone)]
pub(super) struct Token {
    pub(super) secret: Zeroizing<Vec<u8>>,
    pub(super) protocol: u8,
    pub(super) permissions: u8,
    pub(super) rp_id: Option<String>,
    issued: Instant,
    used: bool,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("permissions", &self.permissions)
            .finish_non_exhaustive()
    }
}

impl Token {
    pub(super) fn new(
        protocol: u8,
        permissions: u8,
        rp_id: Option<String>,
    ) -> Result<Self, super::Error> {
        let mut secret = Zeroizing::new(vec![0u8; 32]);
        getrandom::fill(&mut secret).map_err(|_| super::Error)?;
        Ok(Self {
            secret,
            protocol,
            permissions,
            rp_id,
            issued: Instant::now(),
            used: false,
        })
    }

    pub(super) fn expired(&self) -> bool {
        self.issued.elapsed() >= Duration::from_secs(if self.used { 600 } else { 30 })
    }

    pub(super) fn verify(&mut self, protocol: u8, message: &[u8], auth: Option<&[u8]>) -> bool {
        if self.expired()
            || protocol != self.protocol
            || !super::authenticate(protocol, &self.secret, message, auth)
        {
            return false;
        }
        self.used = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_expire_without_sleeping_and_are_protocol_bound() {
        let mut token = Token::new(2, MC, Some("example.com".into())).unwrap();
        let other = Token::new(2, MC, None).unwrap();
        assert_ne!(token.secret, other.secret);
        let mac = software_key_core::digest::hmac(
            software_key_core::digest::HashAlgorithm::Sha256,
            &token.secret,
            b"message",
        )
        .unwrap();
        assert!(!token.verify(1, b"message", Some(&mac[..16])));
        token.issued = Instant::now() - Duration::from_secs(31);
        assert!(!token.verify(2, b"message", Some(&mac)));
        token.issued = Instant::now();
        assert!(token.verify(2, b"message", Some(&mac)));
        token.issued = Instant::now() - Duration::from_secs(599);
        assert!(token.verify(2, b"message", Some(&mac)));
        token.issued = Instant::now() - Duration::from_secs(601);
        assert!(!token.verify(2, b"message", Some(&mac)));
    }
}
