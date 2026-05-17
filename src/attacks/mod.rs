pub mod smallq;
pub mod cube_root;
pub mod fermat;
pub mod wiener;
pub mod hart;
pub mod pollard_rho;
pub mod brent;
pub mod pollard_p1;
pub mod coppersmith;
pub mod common_factors;
pub mod carmichael;
pub mod euler;
pub mod factor_2pn;
pub mod kraitchik;
pub mod lehman;
pub mod lehmer;
pub mod gcd_sequences;
pub mod williams_pp1;
pub mod squfof;
pub mod xyxz;
pub mod novelty_primes;
pub mod dixon;
pub mod comfact_cn;
pub mod non_rsa;
pub mod pollard_strassen;
pub mod common_modulus_related_message;
pub mod hastads;
pub mod same_n_huge_e;
pub mod compositorial_pm1_gcd;
pub mod mersenne_primes;
pub mod multiple_base_inversion_gcd;
pub mod londahl;
pub mod pisano_period;
pub mod highandlowbitsequal;
pub mod system_primes_gcd;
pub mod nullattack;

pub mod binary_poly_factoring;
pub mod boneh_durfee;
pub mod classical_shor;
pub mod ecm;
pub mod factordb;
pub mod lattice;
pub mod neca;
pub mod partial_d;
pub mod partial_q;
pub mod pastctfprimes;
pub mod qicheng;
pub mod qs;
pub mod rapid7primes;
pub mod roca;
pub mod siqs;
pub mod small_crt_exp;
pub mod smallfraction;
pub mod wolframalpha;
pub mod z3_solver;

use crate::attack::RsaAttack;
use crate::key::PublicKey;

/// Build the default attack list for a single key.
/// Speeds match Python RsaCtfTool's speed_enum exactly:
///   fast=2 > medium=1 > slow=0
/// Engine sorts descending so fastest attacks run first.
pub fn single_key_attacks(filter: &[String]) -> Vec<Box<dyn RsaAttack>> {
    let all: Vec<(&str, Box<dyn RsaAttack>)> = vec![
        // --- Fast ---
        ("smallq",                      Box::new(smallq::SmallqAttack)),
        ("mersenne_primes",             Box::new(mersenne_primes::MersennePrimesAttack)),
        ("lucas_gcd",                   Box::new(gcd_sequences::LucasGcdAttack)),
        ("fibonacci_gcd",               Box::new(gcd_sequences::FibonacciGcdAttack)),
        ("nonRSA",                      Box::new(non_rsa::NonRsaAttack)),
        ("system_primes_gcd",           Box::new(system_primes_gcd::SystemPrimesGcdAttack)),
        ("factordb",                    Box::new(factordb::FactorDbAttack)),
        ("pastctfprimes",               Box::new(pastctfprimes::PastCtfPrimesAttack)),
        ("rapid7primes",                Box::new(rapid7primes::Rapid7PrimesAttack)),

        // --- Medium ---
        ("nullattack",                  Box::new(nullattack::NullAttack)),
        ("cube_root",                   Box::new(cube_root::CubeRootAttack)),
        ("fermat",                      Box::new(fermat::FermatAttack)),
        ("hart",                        Box::new(hart::HartAttack)),
        ("wiener",                      Box::new(wiener::WienerAttack)),
        ("pollard_p_1",                 Box::new(pollard_p1::PollardP1Attack)),
        ("carmichael",                  Box::new(carmichael::CarmichaelAttack)),
        ("comfact_cn",                  Box::new(comfact_cn::ComfactCnAttack)),
        ("compositorial_pm1_gcd",       Box::new(compositorial_pm1_gcd::CompositorialPm1GcdAttack)),
        ("coppersmith",                 Box::new(coppersmith::CoppersmithAttack::default())),
        ("factor_2PN",                  Box::new(factor_2pn::Factor2PnAttack)),
        ("factorial_pm1_gcd",           Box::new(gcd_sequences::FactorialPm1GcdAttack)),
        ("fermat_numbers_gcd",          Box::new(gcd_sequences::FermatNumbersGcdAttack)),
        ("highandlowbitsequal",         Box::new(highandlowbitsequal::HighAndLowBitsEqualAttack)),
        ("kraitchik",                   Box::new(kraitchik::KraitchikAttack)),
        ("lehman",                      Box::new(lehman::LehmanAttack)),
        ("lehmer",                      Box::new(lehmer::LehmerAttack)),
        ("mersenne_pm1_gcd",            Box::new(gcd_sequences::MersennePm1GcdAttack)),
        ("multiple_base_inversion_gcd", Box::new(multiple_base_inversion_gcd::MultipleBaseInversionGcdAttack)),
        ("noveltyprimes",               Box::new(novelty_primes::NoveltyPrimesAttack)),
        ("pisano_period",               Box::new(pisano_period::PisanoPeriodAttack)),
        ("pollard_strassen",            Box::new(pollard_strassen::PollardStrassenAttack)),
        ("primorial_pm1_gcd",           Box::new(gcd_sequences::PrimorialPm1GcdAttack)),
        ("SQUFOF",                      Box::new(squfof::SqUfOfAttack)),
        ("boneh_durfee",                Box::new(boneh_durfee::BonehDurfeeAttack)),
        ("classical_shor",              Box::new(classical_shor::ClassicalShorAttack)),
        ("ecm2",                        Box::new(ecm::Ecm2Attack)),
        ("lattice",                     Box::new(lattice::LatticeAttack)),
        ("partial_d",                   Box::new(partial_d::PartialDAttack)),
        ("partial_q",                   Box::new(partial_q::PartialQAttack)),
        ("qicheng",                     Box::new(qicheng::QichengAttack)),
        ("qs",                          Box::new(qs::QsAttack)),
        ("siqs",                        Box::new(siqs::SiqsAttack)),
        ("small_crt_exp",               Box::new(small_crt_exp::SmallCrtExpAttack)),
        ("wolframalpha",                Box::new(wolframalpha::WolframAlphaAttack)),
        ("z3_solver",                   Box::new(z3_solver::Z3SolverAttack)),

        // --- Slow ---
        ("brent",                       Box::new(brent::BrentAttack)),
        ("dixon",                       Box::new(dixon::DixonAttack)),
        ("euler",                       Box::new(euler::EulerAttack)),
        ("londahl",                     Box::new(londahl::LondahlAttack)),
        ("pollard_rho",                 Box::new(pollard_rho::PollardRhoAttack)),
        ("williams_pp1",                Box::new(williams_pp1::WilliamsPp1Attack)),
        ("XYXZ",                        Box::new(xyxz::XyxzAttack)),
        ("binary_polynomial_factoring", Box::new(binary_poly_factoring::BinaryPolyFactoringAttack)),
        ("ecm",                         Box::new(ecm::EcmAttack)),
        ("neca",                        Box::new(neca::NecaAttack)),
        ("roca",                        Box::new(roca::RocaAttack)),
        ("smallfraction",               Box::new(smallfraction::SmallFractionAttack)),
    ];

    all.into_iter()
        .filter(|(name, _)| filter.is_empty() || filter.iter().any(|f| f == "all" || f == name))
        .map(|(_, attack)| attack)
        .collect()
}

fn selected(filter: &[String], name: &str) -> bool {
    filter.is_empty() || filter.iter().any(|f| f == "all" || f == name)
}

/// Build attacks for multi-key mode (common_factors + broadcast + single-key).
pub fn multi_key_attacks(
    keys: Vec<PublicKey>,
    ciphers: Vec<Vec<u8>>,
    filter: &[String],
) -> Vec<Box<dyn RsaAttack>> {
    let mut attacks: Vec<Box<dyn RsaAttack>> = Vec::new();

    if selected(filter, "common_factors") {
        attacks.push(Box::new(common_factors::CommonFactorsAttack { other_keys: keys.clone() }));
    }
    if selected(filter, "common_modulus_related_message") {
        attacks.push(Box::new(common_modulus_related_message::CommonModulusAttack {
            other_keys: keys.clone(),
            other_ciphers: ciphers.clone(),
        }));
    }
    if !ciphers.is_empty() {
        if selected(filter, "hastads") {
            attacks.push(Box::new(hastads::HastadsAttack {
                other_keys: keys.clone(),
                other_ciphers: ciphers.clone(),
            }));
        }
        if selected(filter, "same_n_huge_e") {
            attacks.push(Box::new(same_n_huge_e::SameNHugeEAttack {
                other_keys: keys.clone(),
                other_ciphers: ciphers.clone(),
            }));
        }
    }

    let mut single = single_key_attacks(filter);
    attacks.append(&mut single);
    attacks
}

/// All attack names known to the tool (for --attack validation).
pub fn all_attack_names() -> Vec<&'static str> {
    vec![
        // Single-key fast (9)
        "smallq", "mersenne_primes", "lucas_gcd", "fibonacci_gcd", "nonRSA", "system_primes_gcd",
        "factordb", "pastctfprimes", "rapid7primes",

        // Single-key medium (36 + extra coppersmith + nullattack)
        "nullattack", "cube_root", "fermat", "hart", "wiener", "pollard_p_1",
        "carmichael", "comfact_cn", "compositorial_pm1_gcd", "coppersmith",
        "factor_2PN", "factorial_pm1_gcd", "fermat_numbers_gcd", "highandlowbitsequal",
        "kraitchik", "lehman", "lehmer", "mersenne_pm1_gcd",
        "multiple_base_inversion_gcd", "noveltyprimes", "pisano_period",
        "pollard_strassen", "primorial_pm1_gcd", "SQUFOF",
        "boneh_durfee", "classical_shor", "ecm2", "lattice", "partial_d", "partial_q",
        "qicheng", "qs", "siqs", "small_crt_exp", "wolframalpha", "z3_solver",

        // Single-key slow (10)
        "brent", "dixon", "euler", "londahl", "pollard_rho", "williams_pp1", "XYXZ",
        "binary_polynomial_factoring", "ecm", "neca", "roca", "smallfraction",

        // Multi-key (4)
        "common_factors", "common_modulus_related_message", "hastads", "same_n_huge_e",
    ]
}
