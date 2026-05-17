use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;
use crate::math::common_modulus_attack;

pub struct SameNHugeEAttack {
    pub other_keys: Vec<PublicKey>,
    pub other_ciphers: Vec<Vec<u8>>,
}

impl RsaAttack for SameNHugeEAttack {
    fn name(&self) -> &'static str { "same_n_huge_e" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        if cipher.is_empty() || self.other_ciphers.is_empty() {
            return None;
        }

        let n = &pub_key.n;
        let c1 = Integer::from_digits(cipher[0].as_slice(), rug::integer::Order::Msf);

        for other in &self.other_keys {
            if abort.load(Ordering::Relaxed) { return None; }
            if &other.n != n { continue; }

            let c2 = Integer::from_digits(self.other_ciphers[0].as_slice(), rug::integer::Order::Msf);
            let m = common_modulus_attack(&pub_key.e, &other.e, n, &c1, &c2)?;

            let plain = m.to_digits::<u8>(rug::integer::Order::Msf);
            if plain.is_empty() { continue; }

            log::debug!("[same_n_huge_e] recovered plaintext");
            return Some(AttackResult { priv_key: None, decrypted: vec![plain] });
        }

        None
    }
}
