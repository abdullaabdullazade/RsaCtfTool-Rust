use anyhow::{bail, Context, Result};
use clap::Parser;
use glob::glob;
use rug::Integer;
use rug::integer::Order;
use std::sync::{Arc, atomic::AtomicBool};

use rsa_rust_tool::attack::AttackEngine;
use rsa_rust_tool::attacks;
use rsa_rust_tool::key::{PublicKey, PrivateKey};
use rsa_rust_tool::output::{print_results, PrintArgs};

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn banner() -> &'static str {
    r#"
__________               __________________________ __                .__
\______   \ ___________  \_   ___ \__    ___/\_   _____/|  |_  ____   ____ |  |
 |       _//  ___/\__  \ /    \  \/ |    |    |    __)   \   __\/  _ \ /  _ \|  |
 |    |   \\___ \  / __ \\     \____|    |    |     \     |  | (  <_> |  <_> )  |__
 |____|_  /____  >(____  /\______  /|____|    \___  /     |__|  \____/ \____/|____/
        \/     \/      \/        \/               \/

Disclaimer: this tool is meant for educational purposes, for those doing CTF's first try:

Learning the basis of RSA math, understand number theory, modular arithmetic,
integer factorization, fundamental theorem of arithmetic.

by Abdulla Abdullazade - @abdullaxows
"#
}

// ---------------------------------------------------------------------------
// CLI definition — mirrors RsaCtfTool's argparse exactly
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "RsaRustTool", about = "RSA CTF Tool (Rust port)", long_about = None)]
struct Args {
    /// Public key file. You can use wildcards for multiple keys.
    #[arg(long)]
    publickey: Option<String>,

    /// Output file for results (private keys, plaintext data).
    #[arg(long)]
    output: Option<String>,

    /// Timeout for long attacks in seconds. default is 60s
    #[arg(long, default_value = "60")]
    timeout: u64,

    /// Take n and e from cli and just print a public key then exit
    #[arg(long)]
    createpub: bool,

    /// Just dump the RSA variables from a key - n,e,d,p,q
    #[arg(long)]
    dumpkey: bool,

    /// Extended dump of RSA private variables in --dumpkey mode - dp,dq,pinv,qinv
    #[arg(long)]
    ext: bool,

    /// Decrypt a file, using commas to separate multiple paths
    #[arg(long)]
    decryptfile: Option<String>,

    /// Decrypt a cipher, using commas to separate multiple ciphers
    #[arg(long)]
    decrypt: Option<String>,

    /// Verbose mode
    #[arg(long, default_value = "INFO",
          value_parser = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])]
    verbosity: String,

    /// Display private key if recovered
    #[arg(long)]
    private: bool,

    /// Run tests on attacks
    #[arg(long)]
    tests: bool,

    /// Specify the modulus. format : int or 0xhex
    #[arg(short = 'n')]
    n: Option<String>,

    /// Specify the first prime number. format : int or 0xhex
    #[arg(short = 'p')]
    p: Option<String>,

    /// Specify the second prime number. format : int or 0xhex
    #[arg(short = 'q')]
    q: Option<String>,

    /// Specify the public exponent. format : int or 0xhex
    #[arg(short = 'e')]
    e: Option<String>,

    /// Specify the private exponent. format : int or 0xhex
    #[arg(short = 'd')]
    d: Option<String>,

    /// Specify the private key file
    #[arg(long)]
    key: Option<String>,

    /// Private key password if needed
    #[arg(long)]
    password: Option<String>,

    /// Specify the attack modes. default: all
    #[arg(long, num_args = 1.., default_values = ["all"])]
    attack: Vec<String>,

    /// Check publickey if modulus is well formed before attack
    #[arg(long)]
    check_publickey: bool,

    /// Work with partial private keys
    #[arg(long)]
    partial: bool,

    /// Cleanup *.pub files after finish
    #[arg(long)]
    cleanup: bool,

    /// Show tracebacks
    #[arg(long)]
    withtraceback: bool,

    /// Show modulus value
    #[arg(long)]
    show_modulus: bool,

    /// Check if given key is ROCA vulnerable
    #[arg(long)]
    isroca: bool,

    /// Conspicuous key check
    #[arg(long)]
    isconspicuous: bool,

    /// Send results to factordb (no-op in Rust port — requires network)
    #[arg(long)]
    sendtofdb: bool,

    /// Optionally an estimate of how long one of the primes is for ECM method
    #[arg(long)]
    ecmdigits: Option<u64>,

    /// Convert idrsa.pub to PEM format
    #[arg(long)]
    convert_idrsa_pub: bool,

    /// Number of rayon threads (0 = all cores)
    #[arg(short = 'j', long, default_value = "0")]
    threads: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_int(s: &str) -> Result<Integer> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Integer::parse_radix(h, 16).map(Integer::from)
            .with_context(|| format!("bad hex integer: {}", s))
    } else {
        Integer::parse(s).map(Integer::from)
            .with_context(|| format!("bad decimal integer: {}", s))
    }
}

fn parse_cipher_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if let Ok(n) = parse_int(s) {
        let bytes = n.to_digits::<u8>(Order::MsfBe);
        return Ok(bytes);
    }
    // Try base64
    use base64::Engine;
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
        return Ok(b);
    }
    bail!("Cannot parse ciphertext: {}", s);
}

fn expand_glob(pattern: &str) -> Vec<String> {
    if let Ok(paths) = glob(pattern) {
        paths.filter_map(|p| p.ok())
             .map(|p| p.to_string_lossy().into_owned())
             .collect()
    } else if pattern.contains(',') {
        pattern.split(',').map(str::trim).map(String::from).collect()
    } else {
        vec![pattern.to_string()]
    }
}

fn setup_rayon(threads: usize) -> Result<()> {
    if threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .context("rayon thread pool")?;
    }
    Ok(())
}

fn check_publickey_sanity(pub_key: &PublicKey) -> bool {
    use rsa_rust_tool::attack::gcd;
    if pub_key.n.clone() & 1u32 == 0 {
        log::error!("[!] Public key modulus should be odd.");
        return false;
    }
    if gcd(&pub_key.n, &pub_key.e) > 1 {
        log::error!("[!] Public key modulus is coprime with exponent.");
        return false;
    }
    if pub_key.n <= 3 {
        log::error!("[!] Public key modulus should be > 3.");
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Attack runner — single key
// ---------------------------------------------------------------------------

fn attack_single_key(
    pub_key: &PublicKey,
    cipher: &[Vec<u8>],
    args: &Args,
) -> (Option<PrivateKey>, Vec<Vec<u8>>) {
    // If p and q are already known, build private key directly
    if let (Some(p_str), Some(q_str)) = (&args.p, &args.q) {
        if let (Ok(p), Ok(q)) = (parse_int(p_str), parse_int(q_str)) {
            if let Some(pk) = PrivateKey::new(p, q, pub_key.e.clone(), pub_key.n.clone()) {
                let decrypted = cipher.iter().map(|c| pk.decrypt_raw(c)).collect();
                return (Some(pk), decrypted);
            }
        }
    }

    if args.show_modulus {
        log::info!("modulus: {}", pub_key.n);
    }

    let attack_list = attacks::single_key_attacks(&args.attack);
    let abort = Arc::new(AtomicBool::new(false));
    let engine = AttackEngine::new(attack_list, args.timeout);

    match engine.run(pub_key, cipher, &abort) {
        Some((name, result)) => {
            log::info!("[*] Attack success with {} method!", name);
            (result.priv_key, result.decrypted)
        }
        None => (None, vec![]),
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    // Print banner if no args
    if std::env::args().len() == 1 {
        eprintln!("{}", banner());
        eprintln!("Use --help for usage.");
        std::process::exit(1);
    }

    let args = Args::parse();

    // Setup logging — format matches Python's CustomFormatter: "%(message)s" with ANSI colors
    let level = rsa_rust_tool::output::Verbosity::from_str(&args.verbosity).level();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(level.as_str())
    )
    .format_timestamp(None)
    .format_module_path(false)
    .format_level(false)
    .format(|buf, record| {
        use std::io::Write;
        // ANSI colors matching Python CustomFormatter exactly
        let (prefix, suffix) = match record.level() {
            log::Level::Debug   => ("\x1b[38;21m", "\x1b[0m"),
            log::Level::Info    => ("\x1b[38;21m", "\x1b[0m"),
            log::Level::Warn    => ("\x1b[33;21m", "\x1b[0m"),
            log::Level::Error   => ("\x1b[31;21m", "\x1b[0m"),
            log::Level::Trace   => ("\x1b[31;1m",  "\x1b[0m"),
        };
        writeln!(buf, "{}{}{}", prefix, record.args(), suffix)
    })
    .init();

    if !args.private && !args.tests {
        log::warn!("private argument is not set, the private key will not be displayed, even if recovered.");
    }

    setup_rayon(args.threads)?;

    // Parse scalar CLI values
    let n_val = args.n.as_deref().map(parse_int).transpose()?;
    let p_val = args.p.as_deref().map(parse_int).transpose()?;
    let q_val = args.q.as_deref().map(parse_int).transpose()?;
    let e_val = args.e.as_deref().map(parse_int).transpose()?
        .or_else(|| n_val.as_ref().map(|_| Integer::from(65537u32)));
    let _d_val = args.d.as_deref().map(parse_int).transpose()?;

    // Derive n from p*q if needed
    let n_val = n_val.or_else(|| {
        match (&p_val, &q_val) {
            (Some(p), Some(q)) => Some(p.clone() * q),
            _ => None,
        }
    });

    // --createpub
    if args.createpub {
        if let (Some(n), Some(e)) = (&n_val, &e_val) {
            let pk = PublicKey { n: n.clone(), e: e.clone(), filename: None };
            println!("{}", pk.to_pem());
            return Ok(());
        }
        bail!("--createpub requires -n and -e");
    }

    // --dumpkey on a private key file
    if args.dumpkey && args.key.is_some() {
        log::warn!("--dumpkey with --key not yet supported in this version. Use --publickey.");
    }

    // Resolve ciphertexts
    let mut cipher_bufs: Vec<Vec<u8>> = vec![];

    if let Some(ref dec_str) = args.decrypt {
        for part in dec_str.split(',') {
            cipher_bufs.push(parse_cipher_bytes(part.trim())?);
        }
    }
    if let Some(ref dec_file) = args.decryptfile {
        for path in dec_file.split(',') {
            let data = std::fs::read(path.trim())
                .with_context(|| format!("Cannot read decryptfile: {}", path))?;
            cipher_bufs.push(data);
        }
    }

    let print_args = PrintArgs {
        show_private: args.private,
        dumpkey:      args.dumpkey,
        ext:          args.ext,
        decrypt:      !cipher_bufs.is_empty(),
        output:       args.output.clone(),
    };

    // -----------------------------------------------------------------------
    // Case 1: already have p, q, e, n → no attack needed
    // -----------------------------------------------------------------------
    if let (Some(p), Some(q), Some(e), Some(n)) = (&p_val, &q_val, &e_val, &n_val) {
        log::warn!("[!] You already provided prime factors, no attack needed.");
        let priv_key = PrivateKey::new(p.clone(), q.clone(), e.clone(), n.clone());
        let decrypted: Vec<Vec<u8>> = if let Some(ref pk) = priv_key {
            cipher_bufs.iter().map(|c| pk.decrypt_raw(c)).collect()
        } else { vec![] };
        print_results(&print_args, None, priv_key.as_ref(), &decrypted);
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Case 2: n and e given via CLI → attack
    // -----------------------------------------------------------------------
    if let (Some(n), Some(e)) = (&n_val, &e_val) {
        let pub_key = PublicKey { n: n.clone(), e: e.clone(), filename: None };

        if args.check_publickey && !check_publickey_sanity(&pub_key) {
            std::process::exit(1);
        }

        let (priv_key, decrypted) = attack_single_key(&pub_key, &cipher_bufs, &args);
        print_results(&print_args, None, priv_key.as_ref(), &decrypted);
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Case 3: publickey file(s)
    // -----------------------------------------------------------------------
    if let Some(ref pubkey_pattern) = args.publickey {
        let key_files = expand_glob(pubkey_pattern);
        if key_files.is_empty() {
            bail!("No public key files found matching: {}", pubkey_pattern);
        }

        // Load all keys first (needed for multi-key attacks)
        let mut pub_keys: Vec<PublicKey> = vec![];
        for path in &key_files {
            match PublicKey::from_file(path) {
                Ok(k) => pub_keys.push(k),
                Err(e) => log::error!("[!] Key format not supported: {} — {}", path, e),
            }
        }

        if pub_keys.is_empty() {
            bail!("No keys could be loaded.");
        }

        // --dumpkey without --private: just print n,e and exit
        if args.dumpkey && !args.private && cipher_bufs.is_empty() {
            for pk in &pub_keys {
                if let Some(ref fname) = pk.filename {
                    log::info!("Details for {}:", fname);
                }
                println!("n: {}", pk.n);
                println!("e: {}", pk.e);
            }
            return Ok(());
        }

        for (idx, pub_key) in pub_keys.iter().enumerate() {
            log::info!("\n[*] Testing key {}.", pub_key.filename.as_deref().unwrap_or("(unknown)"));

            if args.check_publickey && !check_publickey_sanity(pub_key) {
                continue;
            }

            // Build attacks (include common_factors if multiple keys)
            let attack_list = if pub_keys.len() > 1 {
                let others: Vec<PublicKey> = pub_keys.iter()
                    .enumerate()
                    .filter(|(i, _)| *i != idx)
                    .map(|(_, k)| k.clone())
                    .collect();
                attacks::multi_key_attacks(others, vec![], &args.attack)
            } else {
                attacks::single_key_attacks(&args.attack)
            };

            let abort = Arc::new(AtomicBool::new(false));
            let engine = AttackEngine::new(attack_list, args.timeout);

            let (priv_key, decrypted) = match engine.run(pub_key, &cipher_bufs, &abort) {
                Some((name, result)) => {
                    log::info!("[*] Attack success with {} method!", name);
                    (result.priv_key, result.decrypted)
                }
                None => (None, vec![]),
            };

            print_results(
                &print_args,
                pub_key.filename.as_deref(),
                priv_key.as_ref(),
                &decrypted,
            );
        }

        if args.cleanup {
            log::info!("Cleanup not applicable (no temp files created).");
        }

        return Ok(());
    }

    // No input provided
    eprintln!("{}", banner());
    eprintln!("No key specified. Use --publickey or -n/-e.");
    std::process::exit(1);
}
