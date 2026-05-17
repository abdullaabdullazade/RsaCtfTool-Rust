use anyhow::{bail, Context, Result};
use base64::Engine;
use rug::Integer;
use rug::integer::Order;

// ---------------------------------------------------------------------------
// DER parser — minimal, handles what we need
// ---------------------------------------------------------------------------

fn der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        bail!("DER: empty length field");
    }
    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else {
        let n = (data[0] & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 1 + n {
            bail!("DER: unsupported length encoding");
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | data[1 + i] as usize;
        }
        Ok((len, 1 + n))
    }
}

/// Parse a SEQUENCE tag, return its contents.
fn der_unwrap_sequence(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() || data[0] != 0x30 {
        bail!("DER: expected SEQUENCE (0x30), got 0x{:02x}", data.get(0).copied().unwrap_or(0));
    }
    let (len, skip) = der_length(&data[1..])?;
    Ok(&data[1 + skip..1 + skip + len])
}

/// Parse one INTEGER from DER, return (value, remaining_bytes).
fn der_parse_integer(data: &[u8]) -> Result<(Integer, &[u8])> {
    if data.is_empty() || data[0] != 0x02 {
        bail!("DER: expected INTEGER (0x02), got 0x{:02x}", data.get(0).copied().unwrap_or(0));
    }
    let (len, skip) = der_length(&data[1..])?;
    let bytes = &data[1 + skip..1 + skip + len];
    // Strip leading sign byte (0x00 for positive big integers)
    let bytes = if bytes.first() == Some(&0x00) { &bytes[1..] } else { bytes };
    let n = Integer::from_digits(bytes, Order::MsfBe);
    Ok((n, &data[1 + skip + len..]))
}

/// Skip over a tag+length+value (any tag).
fn der_skip(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() {
        bail!("DER: nothing to skip");
    }
    let (len, skip) = der_length(&data[1..])?;
    Ok(&data[1 + skip + len..])
}

/// Parse RSA public key (n, e) from PKCS#1 RSAPublicKey DER.
fn parse_pkcs1_pubkey_der(der: &[u8]) -> Result<(Integer, Integer)> {
    let inner = der_unwrap_sequence(der)?;
    let (n, rest) = der_parse_integer(inner)?;
    let (e, _) = der_parse_integer(rest)?;
    Ok((n, e))
}

/// Parse RSA public key (n, e) from PKCS#8 SubjectPublicKeyInfo DER.
fn parse_pkcs8_pubkey_der(der: &[u8]) -> Result<(Integer, Integer)> {
    let outer = der_unwrap_sequence(der)?;
    // Skip the AlgorithmIdentifier SEQUENCE
    let after_alg = der_skip(outer)?;
    // Next is BIT STRING (tag 0x03)
    if after_alg.is_empty() || after_alg[0] != 0x03 {
        bail!("DER: expected BIT STRING (0x03)");
    }
    let (bslen, bsskip) = der_length(&after_alg[1..])?;
    let bs_content = &after_alg[1 + bsskip..1 + bsskip + bslen];
    // BIT STRING: first byte is unused-bits count (always 0 for DER keys)
    let rsa_der = &bs_content[1..];
    parse_pkcs1_pubkey_der(rsa_der)
}

// ---------------------------------------------------------------------------
// DER builder — produces PKCS#1 RSAPrivateKey for PEM export
// ---------------------------------------------------------------------------

fn der_encode_integer(n: &Integer) -> Vec<u8> {
    let bytes: Vec<u8> = n.to_digits(Order::MsfBe);
    let bytes = if bytes.is_empty() {
        vec![0u8]
    } else if bytes[0] & 0x80 != 0 {
        // Need sign byte
        let mut v = vec![0u8];
        v.extend_from_slice(&bytes);
        v
    } else {
        bytes
    };
    let mut out = vec![0x02u8];
    out.extend(der_encode_length(bytes.len()));
    out.extend_from_slice(&bytes);
    out
}

fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn der_encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30u8];
    out.extend(der_encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub n: Integer,
    pub e: Integer,
    pub filename: Option<String>,
}

impl PublicKey {
    /// Load from a PEM file path.
    pub fn from_file(path: &str) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("Cannot read key file: {}", path))?;
        Self::from_pem_bytes(&data, Some(path.to_string()))
    }

    /// Parse from raw PEM bytes (supports both PKCS#8 and PKCS#1 formats).
    pub fn from_pem_bytes(pem: &[u8], filename: Option<String>) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem).context("PEM is not valid UTF-8")?;
        let lines: Vec<&str> = pem_str.lines().collect();

        let header = lines.iter().find(|l| l.starts_with("-----BEGIN")).cloned();
        let header = header.context("No PEM header found")?;

        // Collect base64 body
        let b64: String = lines.iter()
            .filter(|l| !l.starts_with("-----"))
            .cloned()
            .collect();

        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .context("PEM base64 decode failed")?;

        let (n, e) = if header.contains("RSA PUBLIC KEY") {
            parse_pkcs1_pubkey_der(&der)
                .context("PKCS#1 RSA PUBLIC KEY parse failed")?
        } else {
            parse_pkcs8_pubkey_der(&der)
                .context("PKCS#8 PUBLIC KEY parse failed")?
        };

        Ok(Self { n, e, filename })
    }

    /// Export as PKCS#8 SubjectPublicKeyInfo PEM string.
    pub fn to_pem(&self) -> String {
        let rsa_pub = {
            let mut body = Vec::new();
            body.extend(der_encode_integer(&self.n));
            body.extend(der_encode_integer(&self.e));
            der_encode_sequence(&body)
        };

        // AlgorithmIdentifier: OID rsaEncryption + NULL
        let alg_id = {
            // OID 1.2.840.113549.1.1.1
            let oid = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                         0x05, 0x00]; // NULL
            der_encode_sequence(oid)
        };

        // BIT STRING wrapping RSAPublicKey
        let mut bs = vec![0x03u8];
        bs.extend(der_encode_length(rsa_pub.len() + 1));
        bs.push(0x00); // 0 unused bits
        bs.extend(rsa_pub);

        let mut spki_body = alg_id;
        spki_body.extend(bs);
        let spki = der_encode_sequence(&spki_body);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
        let wrapped = b64.as_bytes().chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", wrapped)
    }
}

#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub n: Integer,
    pub e: Integer,
    pub d: Integer,
    pub p: Option<Integer>,
    pub q: Option<Integer>,
}

impl PrivateKey {
    pub fn new(p: Integer, q: Integer, e: Integer, n: Integer) -> Option<Self> {
        let phi = (p.clone() - 1u32) * (q.clone() - 1u32);
        let d = e.clone().invert(&phi).ok()?;
        Some(Self { n, e, d, p: Some(p), q: Some(q) })
    }

    pub fn from_ned(n: Integer, e: Integer, d: Integer) -> Self {
        Self { n, e, d, p: None, q: None }
    }

    /// Export as PKCS#1 RSAPrivateKey PEM.
    pub fn to_pem(&self) -> String {
        let zero = Integer::from(0u32);
        let p = self.p.clone().unwrap_or_else(Integer::new);
        let q = self.q.clone().unwrap_or_else(Integer::new);

        let dp = if p > 0 { self.d.clone().modulo(&(p.clone() - 1u32)) } else { zero.clone() };
        let dq = if q > 0 { self.d.clone().modulo(&(q.clone() - 1u32)) } else { zero.clone() };
        let qi = if p > 0 && q > 0 {
            q.clone().invert(&p).unwrap_or(zero.clone())
        } else { zero };

        let mut body = Vec::new();
        body.extend(der_encode_integer(&Integer::new())); // version = 0
        body.extend(der_encode_integer(&self.n));
        body.extend(der_encode_integer(&self.e));
        body.extend(der_encode_integer(&self.d));
        body.extend(der_encode_integer(&p));
        body.extend(der_encode_integer(&q));
        body.extend(der_encode_integer(&dp));
        body.extend(der_encode_integer(&dq));
        body.extend(der_encode_integer(&qi));

        let der = der_encode_sequence(&body);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let wrapped = b64.as_bytes().chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n", wrapped)
    }

    /// m = c^d mod n
    pub fn decrypt_raw(&self, cipher_bytes: &[u8]) -> Vec<u8> {
        let c = Integer::from_digits(cipher_bytes, Order::MsfBe);
        let m = c.pow_mod(&self.d, &self.n).expect("pow_mod");
        m.to_digits(Order::MsfBe)
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_pem())
    }
}
