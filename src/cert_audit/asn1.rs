// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub use super::pem::{decode_base64, encode_base64, parse_pem_blocks, PemBlock};
use super::types::{CertDate, ParsedCertificate};
use sha2::{Digest, Sha256};

/// Raw ASN.1 DER TLV element descriptor with bounds-checked accessors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerElement<'a> {
    pub tag: u8,
    pub constructed: bool,
    pub value: &'a [u8],
    pub full_len: usize,
}

impl<'a> DerElement<'a> {
    /// Parse a single DER element from the beginning of slice.
    pub fn parse(slice: &'a [u8]) -> Result<(Self, usize), String> {
        if slice.is_empty() {
            return Err("Unexpected EOF reading ASN.1 tag".to_string());
        }
        let tag = slice[0];
        let constructed = (tag & 0x20) != 0;

        if slice.len() < 2 {
            return Err("Unexpected EOF reading ASN.1 length".to_string());
        }

        let (len, len_bytes) = if slice[1] < 0x80 {
            (slice[1] as usize, 1)
        } else {
            let num_octets = (slice[1] & 0x7F) as usize;
            if num_octets == 0 || num_octets > 4 || slice.len() < 2 + num_octets {
                return Err("Invalid or unsupported ASN.1 length octets".to_string());
            }
            let mut val = 0usize;
            for i in 0..num_octets {
                val = (val << 8) | (slice[2 + i] as usize);
            }
            (val, 1 + num_octets)
        };

        let header_len = 1 + len_bytes;
        let full_len = match header_len.checked_add(len) {
            Some(l) => l,
            None => return Err("ASN.1 length calculation integer overflow".to_string()),
        };
        if slice.len() < full_len {
            return Err("ASN.1 length exceeds available buffer".to_string());
        }

        let value = &slice[header_len..full_len];

        Ok((
            DerElement {
                tag,
                constructed,
                value,
                full_len,
            },
            full_len,
        ))
    }

    /// Parse multiple contiguous DER elements from a slice.
    pub fn parse_all(mut slice: &'a [u8]) -> Result<Vec<Self>, String> {
        let mut list = Vec::new();
        while !slice.is_empty() {
            let (elem, consumed) = Self::parse(slice)?;
            if consumed == 0 {
                return Err("Zero bytes consumed in ASN.1 element".to_string());
            }
            list.push(elem);
            slice = &slice[consumed..];
        }
        Ok(list)
    }

    pub fn as_sequence(&self) -> Result<Vec<DerElement<'a>>, String> {
        if (self.tag & 0x1F) != 0x10 {
            return Err(format!(
                "Expected SEQUENCE (0x30), found tag 0x{:02X}",
                self.tag
            ));
        }
        Self::parse_all(self.value)
    }

    pub fn as_set(&self) -> Result<Vec<DerElement<'a>>, String> {
        if (self.tag & 0x1F) != 0x11 {
            return Err(format!("Expected SET (0x31), found tag 0x{:02X}", self.tag));
        }
        Self::parse_all(self.value)
    }

    pub fn as_integer_bytes(&self) -> Result<&'a [u8], String> {
        if self.tag != 0x02 {
            return Err(format!(
                "Expected INTEGER (0x02), found tag 0x{:02X}",
                self.tag
            ));
        }
        Ok(self.value)
    }

    pub fn as_bit_string(&self) -> Result<(&'a [u8], u8), String> {
        if self.tag != 0x03 || self.value.is_empty() {
            return Err(format!(
                "Expected BIT STRING (0x03), found tag 0x{:02X}",
                self.tag
            ));
        }
        let unused_bits = self.value[0];
        Ok((&self.value[1..], unused_bits))
    }

    pub fn as_string(&self) -> Result<String, String> {
        match self.tag {
            0x0C | 0x13 | 0x14 | 0x16 | 0x1A => Ok(String::from_utf8_lossy(self.value).to_string()),
            _ => Err(format!("Unsupported string tag 0x{:02X}", self.tag)),
        }
    }

    pub fn as_oid_string(&self) -> Result<String, String> {
        if self.tag != 0x06 || self.value.is_empty() {
            return Err(format!("Expected OID (0x06), found tag 0x{:02X}", self.tag));
        }
        let first = self.value[0];
        let mut arcs: Vec<u64> = vec![(first / 40) as u64, (first % 40) as u64];

        let mut current_arc = 0u64;
        for &b in &self.value[1..] {
            if current_arc > (u64::MAX >> 7) {
                return Err("ASN.1 OID arc overflowed 64-bit integer".to_string());
            }
            current_arc = (current_arc << 7) | ((b & 0x7F) as u64);
            if (b & 0x80) == 0 {
                arcs.push(current_arc);
                current_arc = 0;
            }
        }
        Ok(arcs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("."))
    }

    pub fn as_time(&self) -> Result<CertDate, String> {
        if !self.value.iter().all(|b| b.is_ascii()) {
            return Err("Time value contains non-ASCII characters".to_string());
        }
        let s = match std::str::from_utf8(self.value) {
            Ok(v) => v,
            Err(_) => return Err("Invalid UTF-8 in time string".to_string()),
        };
        if self.tag == 0x17 {
            // UTCTime: YYMMDDHHMMSSZ
            if s.len() < 13 {
                return Err("UTCTime string too short".to_string());
            }
            let yy = s[0..2].parse::<i32>().map_err(|e| e.to_string())?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            parse_ymdhms_tail(year, &s[2..])
        } else if self.tag == 0x18 {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            if s.len() < 15 {
                return Err("GeneralizedTime string too short".to_string());
            }
            let year = s[0..4].parse::<i32>().map_err(|e| e.to_string())?;
            parse_ymdhms_tail(year, &s[4..])
        } else {
            Err(format!(
                "Expected Time tag (0x17/0x18), found 0x{:02X}",
                self.tag
            ))
        }
    }
}

fn parse_ymdhms_tail(year: i32, s: &str) -> Result<CertDate, String> {
    if s.len() < 10 {
        return Err("Time tail too short".to_string());
    }
    let month = s[0..2].parse::<u8>().map_err(|e| e.to_string())?;
    let day = s[2..4].parse::<u8>().map_err(|e| e.to_string())?;
    let hour = s[4..6].parse::<u8>().map_err(|e| e.to_string())?;
    let minute = s[6..8].parse::<u8>().map_err(|e| e.to_string())?;
    let second = s[8..10].parse::<u8>().map_err(|e| e.to_string())?;

    if !(1..=12).contains(&month) {
        return Err(format!("Invalid month {} in certificate time", month));
    }
    if !(1..=31).contains(&day) {
        return Err(format!("Invalid day {} in certificate time", day));
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err(format!(
            "Invalid time components {:02}:{:02}:{:02}",
            hour, minute, second
        ));
    }

    let unix_timestamp = unix_time_from_ymdhms(year, month, day, hour, minute, second);
    Ok(CertDate {
        year,
        month,
        day,
        hour,
        minute,
        second,
        unix_timestamp,
    })
}

/// Calculate Unix timestamp from UTC date parameters using Gregorian civil calendar arithmetic.
pub fn unix_time_from_ymdhms(year: i32, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> i64 {
    let mut y = year;
    let mut m = month as i32;
    if m <= 2 {
        y -= 1;
        m += 12;
    }
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    (days as i64) * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64)
}

/// Map signature and public key OIDs to canonical human-readable names.
pub fn oid_to_friendly_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.2.1" => "id-ecPublicKey",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10045.3.1.7" => "secp256r1 (NIST P-256)",
        "1.3.132.0.34" => "secp384r1 (NIST P-384)",
        "1.3.132.0.35" => "secp521r1 (NIST P-521)",
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        _ => "Unknown",
    }
}

/// Parse an X.509 Distinguished Name (DN) sequence into an RFC 2253 string.
pub fn parse_distinguished_name(name_elem: &DerElement<'_>) -> String {
    let mut parts = Vec::new();
    if let Ok(rdn_sets) = name_elem.as_sequence() {
        for set in rdn_sets {
            if let Ok(atvs) = set.as_set() {
                for atv in atvs {
                    if let Ok(seq) = atv.as_sequence() {
                        if seq.len() >= 2 {
                            let oid = seq[0].as_oid_string().unwrap_or_default();
                            let friendly = oid_to_friendly_name(&oid);
                            let val = seq[1]
                                .as_string()
                                .unwrap_or_else(|_| hex::encode(seq[1].value));
                            parts.push(format!("{}={}", friendly, val));
                        }
                    }
                }
            }
        }
    }
    if parts.is_empty() {
        "Unknown DN".to_string()
    } else {
        parts.join(", ")
    }
}

/// Parse an X.509 Certificate in binary DER encoding into `ParsedCertificate`.
pub fn parse_x509_certificate(der: &[u8]) -> Result<ParsedCertificate, String> {
    let (root, _) = DerElement::parse(der)?;
    let cert_seq = root.as_sequence()?;
    if cert_seq.len() < 3 {
        return Err("Certificate sequence has fewer than 3 elements".to_string());
    }

    let tbs_elem = &cert_seq[0];
    let tbs_seq = tbs_elem.as_sequence()?;
    if tbs_seq.len() < 6 {
        return Err("TBSCertificate has fewer than 6 elements".to_string());
    }

    let mut idx = 0;
    // Optional version tag [0]
    if (tbs_seq[idx].tag & 0x1F) == 0 {
        idx += 1;
    }

    if idx >= tbs_seq.len() {
        return Err("Missing serialNumber in TBSCertificate".to_string());
    }
    let serial_bytes = tbs_seq[idx].as_integer_bytes()?;
    let serial_hex = hex::encode(serial_bytes);
    idx += 1;

    if idx >= tbs_seq.len() {
        return Err("Missing signature algorithm in TBSCertificate".to_string());
    }
    let sig_algo_seq = tbs_seq[idx].as_sequence()?;
    let sig_algo_oid = sig_algo_seq
        .first()
        .ok_or("Empty signature algorithm sequence")?
        .as_oid_string()?;
    let sig_algo_name = oid_to_friendly_name(&sig_algo_oid).to_string();
    idx += 1;

    if idx >= tbs_seq.len() {
        return Err("Missing issuer in TBSCertificate".to_string());
    }
    let issuer = parse_distinguished_name(&tbs_seq[idx]);
    idx += 1;

    if idx >= tbs_seq.len() {
        return Err("Missing validity in TBSCertificate".to_string());
    }
    let validity_seq = tbs_seq[idx].as_sequence()?;
    if validity_seq.len() < 2 {
        return Err("Validity sequence requires notBefore and notAfter".to_string());
    }
    let not_before = validity_seq[0].as_time()?;
    let not_after = validity_seq[1].as_time()?;
    idx += 1;

    if idx >= tbs_seq.len() {
        return Err("Missing subject in TBSCertificate".to_string());
    }
    let subject = parse_distinguished_name(&tbs_seq[idx]);
    idx += 1;

    if idx >= tbs_seq.len() {
        return Err("Missing SubjectPublicKeyInfo in TBSCertificate".to_string());
    }
    let spki_seq = tbs_seq[idx].as_sequence()?;
    if spki_seq.len() < 2 {
        return Err("SubjectPublicKeyInfo sequence too short".to_string());
    }
    let pk_algo_seq = spki_seq[0].as_sequence()?;
    let pubkey_algo_oid = pk_algo_seq
        .first()
        .ok_or("Missing public key algorithm OID")?
        .as_oid_string()?;
    let pubkey_algo_name = oid_to_friendly_name(&pubkey_algo_oid).to_string();

    let mut ec_curve = None;
    if pk_algo_seq.len() > 1 {
        if let Ok(param_oid) = pk_algo_seq[1].as_oid_string() {
            ec_curve = Some(oid_to_friendly_name(&param_oid).to_string());
        }
    }

    let (pk_bits, _) = spki_seq[1].as_bit_string()?;
    let mut rsa_bits = None;
    let mut public_key_bytes = pk_bits.to_vec();

    if pubkey_algo_oid == "1.2.840.113549.1.1.1" {
        // Parse embedded RSAPublicKey
        if let Ok((rsa_seq_elem, _)) = DerElement::parse(pk_bits) {
            if let Ok(rsa_parts) = rsa_seq_elem.as_sequence() {
                if !rsa_parts.is_empty() {
                    if let Ok(modulus_raw) = rsa_parts[0].as_integer_bytes() {
                        let trimmed = if !modulus_raw.is_empty() && modulus_raw[0] == 0 {
                            &modulus_raw[1..]
                        } else {
                            modulus_raw
                        };
                        rsa_bits = trimmed.len().checked_mul(8);
                        public_key_bytes = trimmed.to_vec();
                    }
                }
            }
        }
    }

    let is_self_signed = issuer == subject && !issuer.is_empty();

    let mut hasher = Sha256::new();
    hasher.update(der);
    let digest = hasher.finalize();
    let fingerprint_sha256 = hex::encode(digest);

    Ok(ParsedCertificate {
        subject,
        issuer,
        serial_hex,
        not_before,
        not_after,
        sig_algo_oid,
        sig_algo_name,
        pubkey_algo_oid,
        pubkey_algo_name,
        rsa_bits,
        ec_curve,
        is_self_signed,
        fingerprint_sha256,
        public_key_bytes,
        raw_der: der.to_vec(),
    })
}

/// Extract RSA modulus bytes and bit length from PKCS#1 or PKCS#8 private key DER.
pub fn parse_rsa_private_key_modulus(der: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let (root, _) = DerElement::parse(der)?;
    let seq = root.as_sequence()?;
    if seq.is_empty() {
        return Err("Empty private key SEQUENCE".to_string());
    }

    // PKCS#1: RSAPrivateKey ::= SEQUENCE { version, modulus: INTEGER, ... }
    if seq.len() >= 3 && seq[0].tag == 0x02 && seq[1].tag == 0x02 {
        let mod_raw = seq[1].as_integer_bytes()?;
        let trimmed = if !mod_raw.is_empty() && mod_raw[0] == 0 {
            &mod_raw[1..]
        } else {
            mod_raw
        };
        let bits = trimmed.len().checked_mul(8).unwrap_or(0);
        return Ok((trimmed.to_vec(), bits));
    }

    // PKCS#8: PrivateKeyInfo ::= SEQUENCE { version, algo: AlgorithmIdentifier, privateKey: OCTET STRING }
    if seq.len() >= 3 && seq[2].tag == 0x04 {
        let inner_bytes = seq[2].value;
        if let Ok((inner_root, _)) = DerElement::parse(inner_bytes) {
            if let Ok(inner_seq) = inner_root.as_sequence() {
                if inner_seq.len() >= 2 && inner_seq[1].tag == 0x02 {
                    let mod_raw = inner_seq[1].as_integer_bytes()?;
                    let trimmed = if !mod_raw.is_empty() && mod_raw[0] == 0 {
                        &mod_raw[1..]
                    } else {
                        mod_raw
                    };
                    let bits = trimmed.len().checked_mul(8).unwrap_or(0);
                    return Ok((trimmed.to_vec(), bits));
                }
            }
        }
    }

    Err("Could not extract RSA modulus from private key DER".to_string())
}
