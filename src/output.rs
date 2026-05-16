/// Output formatting matching RsaCtfTool's print_results / print_decrypted_res exactly.
/// Python uses logger.info() → stderr with ANSI colors (grey for info, bold_red for critical).
/// We replicate this with log::info!() / log::error!() through env_logger.

use crate::key::PrivateKey;

#[derive(Clone, PartialEq)]
pub enum Verbosity { Debug, Info, Warning, Error, Critical }

impl Verbosity {
    pub fn from_str(s: &str) -> Self {
        match s {
            "DEBUG"    => Self::Debug,
            "WARNING"  => Self::Warning,
            "ERROR"    => Self::Error,
            "CRITICAL" => Self::Critical,
            _          => Self::Info,
        }
    }
    pub fn level(&self) -> log::LevelFilter {
        match self {
            Self::Debug    => log::LevelFilter::Debug,
            Self::Info     => log::LevelFilter::Info,
            Self::Warning  => log::LevelFilter::Warn,
            Self::Error    => log::LevelFilter::Error,
            Self::Critical => log::LevelFilter::Error,
        }
    }
}

/// Replicate Python's repr(bytes) for the STR line.
/// Python: repr(b'\x00\xff hello') → "b'\\x00\\xff hello'"
pub fn bytes_repr(b: &[u8]) -> String {
    let inner: String = b.iter().map(|&c| match c {
        b'\'' => "\\'".to_string(),
        b'\\' => "\\\\".to_string(),
        b'\n' => "\\n".to_string(),
        b'\r' => "\\r".to_string(),
        b'\t' => "\\t".to_string(),
        0x20..=0x7e => (c as char).to_string(),
        _ => format!("\\x{:02x}", c),
    }).collect();
    format!("b'{}'", inner)
}

/// Mirrors Python's print_decrypted_res(c, logger).
/// All output via log::info! so it gets ANSI colors and respects --verbosity.
pub fn print_decrypted_res(c: &[u8]) {
    use rug::Integer;
    use rug::integer::Order;

    log::info!("HEX : 0x{}", hex::encode(c));

    let big    = Integer::from_digits(c, Order::MsfBe);
    let little = Integer::from_digits(c, Order::LsfBe);
    log::info!("INT (big endian) : {}", big);
    log::info!("INT (little endian) : {}", little);

    // UTF-8 — suppress only on decode error, like Python's contextlib.suppress
    if let Ok(s) = std::str::from_utf8(c) {
        log::info!("utf-8 : {}", s);
    }

    // UTF-16 — try both LE and BE like Python
    if c.len() % 2 == 0 {
        // Try LE first
        let utf16_le: Vec<u16> = c.chunks_exact(2)
            .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&utf16_le) {
            if s.chars().all(|ch| ch == '\n' || !ch.is_control()) {
                log::info!("utf-16 : {}", s);
            }
        }
        // Try BE
        let utf16_be: Vec<u16> = c.chunks_exact(2)
            .map(|ch| u16::from_be_bytes([ch[0], ch[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&utf16_be) {
            if s.chars().all(|ch| ch == '\n' || !ch.is_control()) {
                log::info!("utf-16 : {}", s);
            }
        }
    }

    log::info!("STR : {}", bytes_repr(c));

    // PKCS#1.5 unpadding — 0x00 0x02 [nonzero bytes] 0x00 [message]
    if c.len() > 3 && c[0] == 0x00 && c[1] == 0x02 {
        if let Some(pos) = c[2..].iter().position(|&b| b == 0x00) {
            let nc = &c[2 + pos + 1..];
            log::info!("\nPKCS#1.5 padding decoded!");
            print_decrypted_res(nc);
        }
    }
}

pub struct PrintArgs {
    pub show_private: bool,
    pub dumpkey: bool,
    pub ext: bool,
    pub decrypt: bool,
    pub output: Option<String>,
}

/// Mirrors Python's print_results(args, publickey, private_key, decrypt).
pub fn print_results(
    args: &PrintArgs,
    publickey_name: Option<&str>,
    priv_key: Option<&PrivateKey>,
    decrypted: &[Vec<u8>],
) {
    let has_output = args.show_private || args.dumpkey
        || (args.decrypt && !decrypted.is_empty());

    if has_output {
        if let Some(name) = publickey_name {
            log::info!("\nResults for {}:", name);
        }
    }

    if let Some(pk) = priv_key {
        if args.show_private {
            log::info!("\nPrivate key :");
            let pem = pk.to_pem();
            if let Some(ref path) = args.output {
                let _ = std::fs::write(path, &pem);
            }
            // Print PEM without trailing newline prefix duplication
            for line in pem.lines() {
                log::info!("{}", line);
            }
        }

        if args.dumpkey {
            log::info!("\nPrivate key details:");
            log::info!("n: {}", pk.n);
            log::info!("e: {}", pk.e);
            log::info!("d: {}", pk.d);
            if let Some(ref p) = pk.p { log::info!("p: {}", p); }
            if let Some(ref q) = pk.q { log::info!("q: {}", q); }

            if args.ext {
                if let (Some(p), Some(q)) = (&pk.p, &pk.q) {
                    let dp = pk.d.clone().modulo(&(p.clone() - 1u32));
                    let dq = pk.d.clone().modulo(&(q.clone() - 1u32));
                    log::info!("dp: {}", dp);
                    log::info!("dq: {}", dq);
                    if let Ok(pinv) = p.clone().invert(q) {
                        log::info!("pinv: {}", pinv);
                    }
                    if let Ok(qinv) = q.clone().invert(p) {
                        log::info!("qinv: {}", qinv);
                    }
                }
            }
        }
    } else {
        // Python: logger.critical("Sorry, cracking failed.") — bold red
        if args.show_private {
            log::error!("Sorry, cracking failed.");
        }
        if args.dumpkey {
            log::error!("Sorry, cracking failed.");
        }
    }

    if args.decrypt {
        if !decrypted.is_empty() {
            log::info!("\nDecrypted data :");
            for c in decrypted {
                if let Some(ref path) = args.output {
                    let _ = std::fs::write(path, c);
                }
                print_decrypted_res(c);
            }
        } else {
            log::error!("Sorry, decrypting failed.");
        }
    }
}
