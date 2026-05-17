use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result};
use crate::key::PublicKey;

pub struct RocaAttack;

fn get_m_prime(key_bits: u32) -> Option<Integer> {
    match key_bits {
        ..=960 => Integer::parse("0x1B3E6C9433A7735FA5FC479FFE4027E13BEA").map(Integer::from).ok(),
        992..=1952 => Integer::parse("0x24683144F41188C2B1D6A217F81F12888E4E6513C43F3F60E72AF8BD9728807483425D1E").map(Integer::from).ok(),
        1984..=3936 => Integer::parse("0x16928DC3E47B44DAF289A60E80E1FC6BD7648D7EF60D1890F3E0A9455EFE0ABDB7A748131413CEBD2E36A76A355C1B664BE462E115AC330F9C13344F8F3D1034A02C23396E6").map(Integer::from).ok(),
        _ => None,
    }
}

pub fn is_roca_vulnerable(n: &Integer) -> bool {
    let m_prime = match get_m_prime(n.significant_bits()) {
        Some(m) => m,
        None => return false,
    };
    let base = Integer::from(65537u32);
    let n_mod_m = n.clone().modulo(&m_prime);
    let mut power = Integer::from(1u32);
    for _ in 0..m_prime.significant_bits() * 2 {
        if power == n_mod_m { return true; }
        power = (power * &base).modulo(&m_prime);
        if power == 1 { break; }
    }
    false
}

impl RsaAttack for RocaAttack {
    fn name(&self) -> &'static str { "roca" }
    fn speed(&self) -> Speed { Speed::Slow }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        if abort.load(Ordering::Relaxed) { return None; }
        if !is_roca_vulnerable(n) {
            log::debug!("[roca] not ROCA-vulnerable");
            return None;
        }

        log::info!("[roca] ROCA-vulnerable, attempting factoring...");

        let m_prime = get_m_prime(n.significant_bits())?;
        let base = Integer::from(65537u32);
        let n_mod_m = n.clone().modulo(&m_prime);
        let order = m_prime.significant_bits() as u64 * 2;

        let mut a3 = 0u64;
        let mut power = Integer::from(1u32);
        for i in 0..order {
            if power == n_mod_m { a3 = i; break; }
            power = (power * &base).modulo(&m_prime);
        }

        let xx = Integer::from(2u32) * n.clone().sqrt() / &m_prime;
        if xx == 0 { return None; }

        let inv_m_n = m_prime.clone().invert(n).ok()?;
        let inf_a = a3 / 2;
        let sup_a = (a3 + order) / 2;

        for a in inf_a..=sup_a {
            if abort.load(Ordering::Relaxed) { return None; }
            let base_a = base.clone().pow_mod(&Integer::from(a), &m_prime).ok()?;
            let known = (base_a * &inv_m_n).modulo(n);

            let mut k = Integer::from(0u32);
            while k <= xx {
                if abort.load(Ordering::Relaxed) { return None; }
                let p_candidate = k.clone() * &m_prime + &known;
                if p_candidate > 1 && p_candidate < *n {
                    let g = Integer::from(p_candidate.gcd_ref(n));
                    if g > 1 && g < *n {
                        let q = n.clone() / &g;
                        log::debug!("[roca] found factor");
                        return make_result(g, q, &pub_key.e, n, cipher);
                    }
                }
                k += 1u32;
            }
        }
        None
    }
}
