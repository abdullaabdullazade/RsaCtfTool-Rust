use rug::Integer;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use rayon::prelude::*;

use crate::key::{PublicKey, PrivateKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Speed { Slow = 0, Medium = 1, Fast = 2 }

/// Result from a successful attack.
pub struct AttackResult {
    pub priv_key: Option<PrivateKey>,
    pub decrypted: Vec<Vec<u8>>,
}

/// Every attack module implements this trait.
pub trait RsaAttack: Send + Sync {
    fn name(&self) -> &'static str;
    fn speed(&self) -> Speed;

    /// Returns Some on success or None on failure.
    /// `cipher` is a list of raw ciphertext byte sequences.
    fn run(
        &self,
        pub_key: &PublicKey,
        cipher: &[Vec<u8>],
        abort: &Arc<AtomicBool>,
    ) -> Option<AttackResult>;

    /// Whether this attack can run (e.g. required binaries present). Default: always true.
    fn can_run(&self) -> bool { true }
}

pub struct AttackEngine {
    attacks: Vec<Box<dyn RsaAttack>>,
    pub timeout_secs: u64,
}

impl AttackEngine {
    pub fn new(mut attacks: Vec<Box<dyn RsaAttack>>, timeout_secs: u64) -> Self {
        // Sort by speed descending (fast first), matching RsaCtfTool's sort(key=lambda x: x.speed, reverse=True)
        attacks.sort_by(|a, b| b.speed().cmp(&a.speed()));
        Self { attacks, timeout_secs }
    }

    /// Run all attacks in parallel; return the first success.
    pub fn run(
        &self,
        pub_key: &PublicKey,
        cipher: &[Vec<u8>],
        abort: &Arc<AtomicBool>,
    ) -> Option<(String, AttackResult)> {
        let (tx, rx) = std::sync::mpsc::channel::<(String, AttackResult)>();

        self.attacks.par_iter().for_each(|attack| {
            if abort.load(Ordering::Relaxed) { return; }
            if !attack.can_run() { return; }

            let name = attack.name();
            log::info!("[*] Performing {} attack.", name);

            let t0 = std::time::Instant::now();
            match attack.run(pub_key, cipher, abort) {
                Some(result) => {
                    let elapsed = t0.elapsed().as_secs_f64();
                    log::info!("[+] Time elapsed: {:.4} sec.", elapsed);
                    log::info!("[*] Attack success with {} method!", name);
                    abort.store(true, Ordering::SeqCst);
                    let _ = tx.send((name.to_string(), result));
                }
                None => {
                    if !abort.load(Ordering::Relaxed) {
                        let elapsed = t0.elapsed().as_secs_f64();
                        log::info!("[+] Time elapsed: {:.4} sec.", elapsed);
                    }
                }
            }
        });

        drop(tx);
        rx.try_recv().ok()
    }
}

// ---------------------------------------------------------------------------
// Shared math helpers used by multiple attacks
// ---------------------------------------------------------------------------

pub fn mod_inverse(a: &Integer, m: &Integer) -> Option<Integer> {
    a.clone().invert(m).ok()
}

pub fn compute_private_key(p: Integer, q: Integer, e: &Integer, n: &Integer) -> Option<PrivateKey> {
    PrivateKey::new(p, q, e.clone(), n.clone())
}

/// Decrypt all ciphertexts with the private key.
pub fn decrypt_all(priv_key: &PrivateKey, cipher: &[Vec<u8>]) -> Vec<Vec<u8>> {
    cipher.iter().map(|c| priv_key.decrypt_raw(c)).collect()
}

/// Build AttackResult from p, q and optionally decrypt ciphertexts.
pub fn make_result(
    p: Integer,
    q: Integer,
    e: &Integer,
    n: &Integer,
    cipher: &[Vec<u8>],
) -> Option<AttackResult> {
    let pk = compute_private_key(p, q, e, n)?;
    let decrypted = if cipher.is_empty() { vec![] } else { decrypt_all(&pk, cipher) };
    Some(AttackResult { priv_key: Some(pk), decrypted })
}

/// Integer square root — returns floor(sqrt(n)).
pub fn isqrt(n: &Integer) -> Integer {
    if *n <= 0 { return Integer::new(); }
    n.clone().sqrt()
}

/// Integer square root with remainder: returns (s, r) where n = s^2 + r.
pub fn isqrt_rem(n: Integer) -> (Integer, Integer) {
    n.sqrt_rem(Integer::new())
}

/// Check if n is a perfect square; returns Some(sqrt) or None.
pub fn is_square(n: &Integer) -> Option<Integer> {
    if *n < 0 { return None; }
    let (s, r) = n.clone().sqrt_rem(Integer::new());
    if r == 0 { Some(s) } else { None }
}

/// GCD of two integers.
pub fn gcd(a: &Integer, b: &Integer) -> Integer {
    a.clone().gcd(b)
}

/// Primes up to limit via sieve of Eratosthenes.
pub fn primes_up_to(limit: usize) -> Vec<u64> {
    let mut sieve = vec![true; limit + 1];
    sieve[0] = false;
    if limit > 0 { sieve[1] = false; }
    let mut i = 2;
    while i * i <= limit {
        if sieve[i] {
            let mut j = i * i;
            while j <= limit {
                sieve[j] = false;
                j += i;
            }
        }
        i += 1;
    }
    sieve.iter().enumerate()
        .filter(|(_, &p)| p)
        .map(|(i, _)| i as u64)
        .collect()
}
