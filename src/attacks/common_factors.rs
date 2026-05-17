use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, gcd};
use crate::key::{PublicKey, PrivateKey};

pub struct CommonFactorsAttack {
    pub other_keys: Vec<PublicKey>,
}

impl RsaAttack for CommonFactorsAttack {
    fn name(&self) -> &'static str { "common_factors" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        for other in &self.other_keys {
            if other.n == pub_key.n { continue; }
            let g = gcd(&pub_key.n, &other.n);
            if g > 1 && g < pub_key.n {
                let q = pub_key.n.clone() / &g;
                log::info!("[common_factors] Found common factor with another key!");
                let pk = PrivateKey::new(g, q, pub_key.e.clone(), pub_key.n.clone())?;
                let decrypted = cipher.iter().map(|c| pk.decrypt_raw(c)).collect();
                return Some(AttackResult { priv_key: Some(pk), decrypted });
            }
        }
        None
    }
}
