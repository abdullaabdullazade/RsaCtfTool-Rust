use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};
use crate::math::{gcdext, pow_mod_signed};

pub struct CommonModulusAttack {
    pub other_keys: Vec<PublicKey>,
    pub other_ciphers: Vec<Vec<u8>>,
}

impl RsaAttack for CommonModulusAttack {
    fn name(&self) -> &'static str { "common_modulus_related_message" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;
        let e1 = &pub_key.e;

        for (other_key, c2_bytes) in self.other_keys.iter().zip(self.other_ciphers.iter()) {
            if &other_key.n != n { continue; }
            let e2 = &other_key.e;

            if cipher.is_empty() || c2_bytes.is_empty() { continue; }

            let c1 = Integer::from_digits(&cipher[0], rug::integer::Order::Msf);
            let c2 = Integer::from_digits(c2_bytes, rug::integer::Order::Msf);

            // (g, s1, s2) where g = gcd(e1,e2), e1*s1 + e2*s2 = g
            let (g, s1, s2) = gcdext(e1, e2);
            if g != 1 { continue; }

            // m = c1^s1 * c2^s2 mod n (s1 or s2 may be negative)
            let m1 = pow_mod_signed(&c1, &s1, n)?;
            let m2 = pow_mod_signed(&c2, &s2, n)?;
            let m = (m1 * m2).modulo(n);

            log::debug!("[common_modulus] recovered m={}", &m);

            let m_bytes = m.to_digits::<u8>(rug::integer::Order::Msf);
            let priv_key = PrivateKey::from_ned(n.clone(), e1.clone(), Integer::new());
            return Some(AttackResult {
                priv_key: Some(priv_key),
                decrypted: vec![m_bytes],
            });
        }
        None
    }
}
