/// system_primes_gcd: GCD of N against well-known crypto/system constants.
/// These are primes from OpenSSL, NIST, RFC primes, Diffie-Hellman groups, etc.
/// Matches Python's system_primes_gcd attack.

use rug::Integer;
use std::sync::{Arc, atomic::AtomicBool};
use crate::attack::{RsaAttack, Speed, AttackResult, make_result, gcd};
use crate::key::PublicKey;
use crate::math::is_prime;

pub struct SystemPrimesGcdAttack;

// Well-known Diffie-Hellman group primes and crypto constants
// These are MODP group primes from RFC 3526, RFC 5114, etc.
static SYSTEM_PRIMES_HEX: &[&str] = &[
    // MODP Group 1 (768-bit) RFC 2409
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    // MODP Group 2 (1024-bit) RFC 2409
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    // MODP Group 5 (1536-bit) RFC 3526
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    // MODP Group 14 (2048-bit) RFC 3526
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    // Safe prime p for X9.42 (1024-bit)
    "FCA682CE8E12CABA26EFCCF7110E526DB078B05EDECBCD1EB4A208F3AE1617AE01F35B91A47E6DF63413C5E12ED0899BCD132AE7261767A1D55CD7AA7617C40D41AC61D5DA82FA94938F2F19E3A4C6573E7B8E8B0F01A9E02CB8E14CF4E31F5A99E3FA0E1BD3A1FD8854E6A7B63FE36E31CEB6C5E7B5D9DD3F6CB65F7E1C97A5C51D6B99FCF47A3AEB21396D02F3B3C0773B8F2E7A3DB6A8B72D4D7649D19EBFB56E01E30BA89866FCA5DBFB3B263AB7FAB820E24E33870BB77B1B0B92E2D27EA89E1EF5B01F195BC5183C81D73BAEF7F2CE7ADDA2FBEBA2A7DC31CA26BC00D081693BCC52597A5E8F23B0A00DEC7B45041826A9CF7D35C6E42B2C37BE7D707C83C4D40C63AF0592D4FD0BCFE9956EC79B7B5EC1E5B7823BF3C01",
];

impl RsaAttack for SystemPrimesGcdAttack {
    fn name(&self) -> &'static str { "system_primes_gcd" }
    fn speed(&self) -> Speed { Speed::Fast }

    fn run(&self, pub_key: &PublicKey, cipher: &[Vec<u8>], _abort: &Arc<AtomicBool>) -> Option<AttackResult> {
        let n = &pub_key.n;

        for &hex_str in SYSTEM_PRIMES_HEX {
            let cleaned: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if let Ok(prime_int) = Integer::parse_radix(&cleaned, 16).map(Integer::from) {
                // Test prime and prime ± 1
                for candidate in [prime_int.clone() - 1u32, prime_int.clone(), prime_int.clone() + 1u32] {
                    if candidate < 2 { continue; }
                    let g = gcd(&candidate, n);
                    if g > 1 && g < *n {
                        let q = n.clone() / &g;
                        if is_prime(&g) || is_prime(&q) {
                            log::debug!("[system_primes_gcd] found factor from crypto constant");
                            return make_result(g, q, &pub_key.e, n, cipher);
                        }
                    }
                }
            }
        }

        // Also test small well-known primes used in DH parameters
        let small_primes: &[u64] = &[
            // RFC 2631 generator primes
            1073741789, 1073741827, 1073741833, 1073741909, 1073741939,
            2147483647, // 2^31-1 (Mersenne prime)
            4294967291, // near 2^32
        ];
        for &p in small_primes {
            let prime_int = Integer::from(p);
            let g = gcd(&prime_int, n);
            if g > 1 && g < *n {
                let q = n.clone() / &g;
                log::debug!("[system_primes_gcd] found small prime factor");
                return make_result(g, q, &pub_key.e, n, cipher);
            }
        }

        None
    }
}
