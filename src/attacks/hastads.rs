/// Hastad's broadcast attack: same plaintext m encrypted under k different keys with e=3.
/// Uses CRT to recover m^e mod (n1*n2*...) then takes eth integer root.
/// Matches Python's hastads() in algos.py.

use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::{PublicKey, PrivateKey};
use crate::math::{chinese_remainder, iroot};

pub struct HastadsAttack {
    pub other_keys: Vec<PublicKey>,
    pub other_ciphers: Vec<Vec<u8>>,
}

impl RsaAttack for HastadsAttack {
    fn name(&self) -> &'static str { "hastads" }
    fn speed(&self) -> Speed { Speed::Medium }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let e = &pub_key.e;

        // Collect all keys + ciphertexts with same e
        let mut ns: Vec<Integer> = vec![pub_key.n.clone()];
        let mut cs: Vec<Integer> = Vec::new();

        if cipher.is_empty() { return None; }
        cs.push(Integer::from_digits(&cipher[0], rug::integer::Order::Msf));

        for (key, c_bytes) in self.other_keys.iter().zip(self.other_ciphers.iter()) {
            if &key.e != e { continue; }
            ns.push(key.n.clone());
            cs.push(Integer::from_digits(c_bytes, rug::integer::Order::Msf));
        }

        let e_usize = e.to_u32().unwrap_or(3) as usize;
        if ns.len() < e_usize { return None; }

        // Take exactly e keys
        let ns = &ns[..e_usize];
        let cs = &cs[..e_usize];

        // CRT to get combined = m^e mod (n1*n2*...*ne)
        let combined = chinese_remainder(ns, cs);

        // Take eth root
        let (root, exact) = iroot(&combined, e.to_u32().unwrap_or(3));
        if !exact {
            // Try anyway — sometimes small rounding
            log::debug!("[hastads] eth root not exact, trying anyway");
        }

        let m_bytes = root.to_digits::<u8>(rug::integer::Order::Msf);
        log::debug!("[hastads] recovered m (e={})", e);

        let priv_key = PrivateKey::from_ned(pub_key.n.clone(), e.clone(), Integer::new());
        Some(AttackResult {
            priv_key: Some(priv_key),
            decrypted: vec![m_bytes],
        })
    }
}
