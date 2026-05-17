use rug::{Integer, ops::Pow};
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult};
use crate::key::PublicKey;

pub struct CubeRootAttack;

fn eth_root(c: &Integer, e: u32) -> Option<Integer> {
    // Binary search: find m such that m^e == c
    let mut lo = Integer::new();
    let mut hi = c.clone();

    while lo < hi {
        let mid = (lo.clone() + &hi + 1u32) / 2u32;
        let mid_e = mid.clone().pow(e);
        use std::cmp::Ordering::*;
        match mid_e.cmp(c) {
            Equal => return Some(mid),
            Less  => lo = mid,
            Greater => hi = mid - 1u32,
        }
    }
    // Check lo itself
    if lo.clone().pow(e) == *c { Some(lo) } else { None }
}

impl RsaAttack for CubeRootAttack {
    fn name(&self) -> &'static str { "cube_root" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let e = pub_key.e.to_u32()?;
        if e != 3 && e != 5 { return None; }
        if cipher.is_empty() {
            log::info!("[-] No ciphertexts specified, skipping the cube_root test...");
            return None;
        }

        use rug::integer::Order;
        let mut results = vec![];
        for c_bytes in cipher {
            let c = Integer::from_digits(c_bytes, Order::MsfBe);
            let m = eth_root(&c, e)?;
            let m_bytes = m.to_digits::<u8>(Order::MsfBe);
            results.push(m_bytes);
        }

        Some(AttackResult { priv_key: None, decrypted: results })
    }
}
