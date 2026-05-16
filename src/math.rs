/// Shared cryptographic math functions — mirrors RsaCtfTool's number_theory.py.
/// All arithmetic uses rug::Integer (GMP backend) for full precision.

use rug::{Integer, ops::Pow};

// ---------------------------------------------------------------------------
// Primality
// ---------------------------------------------------------------------------

/// Miller-Rabin primality test (k=25 rounds → error prob < 4^-25).
pub fn is_prime(n: &Integer) -> bool {
    if *n < 2 { return false; }
    if *n == 2 || *n == 3 { return true; }
    if n.clone() & 1u32 == 0 { return false; }

    // Small primes shortcut
    for &p in &[3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        if *n == p { return true; }
        if n.clone().modulo(&Integer::from(p)) == 0 { return false; }
    }

    // Write n-1 as 2^r * d
    let n1 = n.clone() - 1u32;
    let r = n1.find_one(0).unwrap_or(0);
    let d = n1.clone() >> r;

    // Deterministic witnesses for n < 3.3e24 (covers all 64-bit numbers)
    let thresh1 = Integer::from(3_215_031_751u64);
    let thresh2 = Integer::parse("3317044064679887385961981").map(Integer::from).unwrap();
    let witnesses: &[u64] = if *n < thresh1 {
        &[2, 3, 5, 7]
    } else if *n < thresh2 {
        &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    } else {
        &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
    };

    'witness: for &a in witnesses {
        let a = Integer::from(a);
        if a >= *n { continue; }
        let mut x = a.pow_mod(&d, n).expect("pow_mod");
        let n1 = n.clone() - 1u32;
        if x == 1 || x == n1 { continue; }
        for _ in 0..r - 1 {
            x = x.clone().pow_mod(&Integer::from(2u32), n).expect("pow_mod");
            if x == n1 { continue 'witness; }
        }
        return false;
    }
    true
}

/// Next prime strictly greater than n.
pub fn next_prime(n: &Integer) -> Integer {
    let mut candidate = n.clone() + 1u32;
    if candidate <= 2 { return Integer::from(2u32); }
    if candidate.clone() & 1u32 == 0 { candidate += 1u32; }
    while !is_prime(&candidate) {
        candidate += 2u32;
    }
    candidate
}

// ---------------------------------------------------------------------------
// Integer roots
// ---------------------------------------------------------------------------

/// Integer kth root — floor(n^(1/k)).
pub fn iroot(n: &Integer, k: u32) -> (Integer, bool) {
    if k == 0 { panic!("iroot: k must be > 0"); }
    if k == 1 { return (n.clone(), true); }
    if k == 2 {
        let (s, r) = n.clone().sqrt_rem(Integer::new());
        return (s, r == 0);
    }
    if *n <= 0 { return (Integer::new(), *n == 0); }

    // Newton's method for integer kth root
    let bits = n.significant_bits();
    let guess_bits = (bits + k - 1) / k + 2;
    let mut x = Integer::from(1u32) << guess_bits;

    loop {
        // x_new = ((k-1)*x + n/x^(k-1)) / k
        let xk1 = x.clone().pow(k - 1);
        let (q, _) = n.clone().div_rem(xk1);
        let x_new = (Integer::from(k - 1) * &x + q) / Integer::from(k);
        if x_new >= x { break; }
        x = x_new;
    }

    // Verify and potentially adjust by ±1
    let xk = x.clone().pow(k);
    if xk == *n { return (x, true); }
    if xk > *n {
        let x1 = x.clone() - 1u32;
        let x1k = x1.clone().pow(k);
        return (x1.clone(), x1k == *n);
    }
    let x1 = x.clone() + 1u32;
    let x1k = x1.clone().pow(k);
    if x1k == *n { return (x1, true); }
    (x, false)
}

/// Floor(log_b(n)).
pub fn ilogb(n: &Integer, b: u64) -> u32 {
    let mut count = 0u32;
    let mut x = n.clone();
    let bint = Integer::from(b);
    while x >= bint {
        x /= &bint;
        count += 1;
    }
    count
}

// ---------------------------------------------------------------------------
// Sequences
// ---------------------------------------------------------------------------

/// nth Fibonacci number (F_0=0, F_1=1).
pub fn fibonacci(n: u64) -> Integer {
    if n == 0 { return Integer::new(); }
    let mut a = Integer::new();
    let mut b = Integer::from(1u32);
    for _ in 1..n {
        let t = a + &b;
        a = b;
        b = t;
    }
    b
}

/// nth Lucas number (L_0=2, L_1=1).
pub fn lucas(n: u64) -> Integer {
    if n == 0 { return Integer::from(2u32); }
    let mut a = Integer::from(2u32);
    let mut b = Integer::from(1u32);
    for _ in 1..n {
        let t = a + &b;
        a = b;
        b = t;
    }
    b
}

/// mlucas: multiply along a Lucas sequence V mod n. Used by Williams P+1.
/// Computes V_a(v) mod n where V is the Lucas V sequence with parameter v.
pub fn mlucas(v: &Integer, a: &Integer, n: &Integer) -> Integer {
    let mut v1 = v.clone();
    let mut v2 = (v.clone() * v - 2u32).modulo(n);
    let bits = a.significant_bits();

    // Process from the second-most-significant bit
    if bits < 2 {
        return v1;
    }

    for bit in (0..bits - 1).rev() {
        if a.get_bit(bit) {
            // bit = 1: v1 = v1*v2 - v; v2 = v2^2 - 2
            let new_v1 = (v1.clone() * &v2 - v).modulo(n);
            let new_v2 = (v2.clone() * &v2 - 2u32).modulo(n);
            v1 = new_v1;
            v2 = new_v2;
        } else {
            // bit = 0: v2 = v1*v2 - v; v1 = v1^2 - 2
            let new_v2 = (v1.clone() * &v2 - v).modulo(n);
            let new_v1 = (v1.clone() * &v1 - 2u32).modulo(n);
            v1 = new_v1;
            v2 = new_v2;
        }
    }
    v1
}

// ---------------------------------------------------------------------------
// Extended GCD and inverse
// ---------------------------------------------------------------------------

/// Extended Euclidean algorithm. Returns (g, s, t) where g = gcd(a,b), a*s + b*t = g.
pub fn gcdext(a: &Integer, b: &Integer) -> (Integer, Integer, Integer) {
    let (g, s, t) = a.clone().extended_gcd(b.clone(), Integer::new());
    (g, s, t)
}

/// Modular inverse of a mod m. Returns None if gcd(a,m) != 1.
pub fn modinv(a: &Integer, m: &Integer) -> Option<Integer> {
    a.clone().invert(m).ok()
}

/// a^b mod n where b can be negative.
pub fn pow_mod_signed(a: &Integer, b: &Integer, n: &Integer) -> Option<Integer> {
    if *b >= 0 {
        a.clone().pow_mod(b, n).ok()
    } else {
        let a_inv = modinv(a, n)?;
        let b_pos = b.clone().abs();
        a_inv.pow_mod(&b_pos, n).ok()
    }
}

// ---------------------------------------------------------------------------
// Chinese Remainder Theorem
// ---------------------------------------------------------------------------

/// Chinese Remainder Theorem. Given moduli m[] and remainders a[], find x such that
/// x ≡ a[i] (mod m[i]) for all i.
pub fn chinese_remainder(moduli: &[Integer], remainders: &[Integer]) -> Integer {
    let n: Integer = moduli.iter().fold(Integer::from(1u32), |acc, m| acc * m);
    let mut s = Integer::new();
    for (mi, ai) in moduli.iter().zip(remainders.iter()) {
        let ni = n.clone() / mi;
        if let Some(inv) = modinv(&ni, mi) {
            s += ni * inv * ai;
            s %= &n;
        }
    }
    s.modulo(&n)
}

// ---------------------------------------------------------------------------
// Factorization helpers
// ---------------------------------------------------------------------------

/// Given n and phi(n), find p and q.
/// Solves x^2 - (n - phi + 1)*x + n = 0.
pub fn factor_from_n_phi(n: &Integer, phi: &Integer) -> Option<(Integer, Integer)> {
    // b = n - phi + 1 = p + q
    let b = n.clone() - phi + 1u32;
    // disc = b^2 - 4n
    let disc: Integer = b.clone() * &b - Integer::from(4u32) * n;
    if disc < 0 { return None; }
    let (sqrt_disc, rem) = disc.sqrt_rem(Integer::new());
    if rem != 0 { return None; }
    let p = (b.clone() + &sqrt_disc) / 2u32;
    let q = (b - &sqrt_disc) / 2u32;
    if p.clone() * &q == *n && p > 1 && q > 1 {
        Some((p, q))
    } else {
        None
    }
}

/// Common-modulus related-message attack.
/// Given e1, e2, c1=m^e1 mod n, c2=m^e2 mod n with gcd(e1,e2)=1, find m.
pub fn common_modulus_attack(
    e1: &Integer,
    e2: &Integer,
    n: &Integer,
    c1: &Integer,
    c2: &Integer,
) -> Option<Integer> {
    let (g, a, b) = gcdext(e1, e2);
    if g != 1 { return None; }
    let t1 = pow_mod_signed(c1, &a, n)?;
    let t2 = pow_mod_signed(c2, &b, n)?;
    Some((t1 * t2).modulo(n))
}
