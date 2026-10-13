// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::asn1::encode_base64;
use crate::error::{CarverError, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Deterministic ASN.1 DER and PEM fixture generator for testing and firmware synthesis.
pub struct CertSynth;

impl CertSynth {
    /// Generate a valid 2048-bit RSA certificate signed with SHA-256.
    pub fn build_valid_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(256, 0x11);
        build_cert_internal(
            "CN=Router Admin, O=Embedded Systems, C=US",
            "CN=Enterprise Root CA, O=Trust Authority, C=US",
            "250101000000Z",
            "270101000000Z",
            &OID_SHA256_WITH_RSA,
            &modulus,
        )
    }

    /// Generate an expired certificate (expired in 2021).
    pub fn build_expired_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(256, 0x22);
        build_cert_internal(
            "CN=Old Gateway, O=Legacy IoT, C=US",
            "CN=Old Root CA, O=Legacy IoT, C=US",
            "180101000000Z",
            "210101000000Z",
            &OID_SHA256_WITH_RSA,
            &modulus,
        )
    }

    /// Generate a certificate expiring soon (<30 days from reference 2026-10-13, e.g. expires 2026-10-25).
    pub fn build_expiring_soon_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(256, 0x33);
        build_cert_internal(
            "CN=Expiring Service, O=Cloud Sync, C=US",
            "CN=Enterprise Root CA, O=Trust Authority, C=US",
            "251025000000Z",
            "261025000000Z",
            &OID_SHA256_WITH_RSA,
            &modulus,
        )
    }

    /// Generate a certificate signed with broken MD5 hash algorithm.
    pub fn build_weak_md5_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(256, 0x44);
        build_cert_internal(
            "CN=Insecure Gateway, O=Old Network, C=US",
            "CN=Insecure Root CA, O=Old Network, C=US",
            "250101000000Z",
            "280101000000Z",
            &OID_MD5_WITH_RSA,
            &modulus,
        )
    }

    /// Generate a certificate signed with deprecated SHA-1 hash algorithm.
    pub fn build_weak_sha1_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(256, 0x55);
        build_cert_internal(
            "CN=Legacy AP, O=Vendor Hardware, C=US",
            "CN=Vendor Root CA, O=Vendor Hardware, C=US",
            "250101000000Z",
            "280101000000Z",
            &OID_SHA1_WITH_RSA,
            &modulus,
        )
    }

    /// Generate a certificate with a vulnerable 512-bit RSA public key and its matching private key.
    pub fn build_weak_rsa512_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let modulus = make_dummy_modulus(64, 0x66);
        let cert = build_cert_internal(
            "CN=Weak Key Device, O=Vendor Corp, C=US",
            "CN=Vendor Root CA, O=Vendor Corp, C=US",
            "250101000000Z",
            "280101000000Z",
            &OID_SHA256_WITH_RSA,
            &modulus,
        );
        let key = build_rsa_private_key_der(&modulus);
        (cert, key)
    }

    /// Generate a certificate with a deprecated 1024-bit RSA public key.
    pub fn build_deprecated_rsa1024_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(128, 0x77);
        build_cert_internal(
            "CN=Legacy 1024 Device, O=Vendor Corp, C=US",
            "CN=Vendor Root CA, O=Vendor Corp, C=US",
            "250101000000Z",
            "280101000000Z",
            &OID_SHA256_WITH_RSA,
            &modulus,
        )
    }

    /// Generate a self-signed certificate where Subject equals Issuer.
    pub fn build_self_signed_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(256, 0x88);
        build_cert_internal(
            "CN=SelfSigned Router, O=SelfSigned Corp, C=US",
            "CN=SelfSigned Router, O=SelfSigned Corp, C=US",
            "250101000000Z",
            "280101000000Z",
            &OID_SHA256_WITH_RSA,
            &modulus,
        )
    }

    /// Generate a certificate with anomalous validity period (>30 years).
    pub fn build_anomalous_validity_cert() -> Vec<u8> {
        let modulus = make_dummy_modulus(256, 0x99);
        build_cert_internal(
            "CN=Permanent Cert, O=IoT Indefinite, C=US",
            "CN=IoT Root CA, O=IoT Indefinite, C=US",
            "250101000000Z",
            "20650101000000Z", // 2065 GeneralizedTime (40 years duration)
            &OID_SHA256_WITH_RSA,
            &modulus,
        )
    }

    /// Convert DER bytes to PEM string with custom label.
    pub fn to_pem(label: &str, der: &[u8]) -> String {
        let b64 = encode_base64(der);
        let mut out = format!("-----BEGIN {}-----\n", label);
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            out.push('\n');
        }
        out.push_str(&format!("-----END {}-----\n", label));
        out
    }

    /// Populate a directory on disk simulating an embedded `/etc/ssl/certs` store with keys.
    pub fn write_synthetic_cert_store(dir: &Path) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(dir).map_err(CarverError::Io)?;
        let mut created = Vec::new();

        let cert1 = Self::build_valid_cert();
        let path1 = dir.join("valid_server.crt");
        fs::write(&path1, Self::to_pem("CERTIFICATE", &cert1)).map_err(CarverError::Io)?;
        created.push(path1);

        let cert2 = Self::build_expired_cert();
        let path2 = dir.join("expired_ca.pem");
        fs::write(&path2, Self::to_pem("CERTIFICATE", &cert2)).map_err(CarverError::Io)?;
        created.push(path2);

        let cert3 = Self::build_weak_md5_cert();
        let path3 = dir.join("weak_md5.crt");
        fs::write(&path3, &cert3).map_err(CarverError::Io)?; // Raw DER
        created.push(path3);

        let (cert4, key4) = Self::build_weak_rsa512_cert_and_key();
        let path4_crt = dir.join("device_512.crt");
        fs::write(&path4_crt, Self::to_pem("CERTIFICATE", &cert4)).map_err(CarverError::Io)?;
        created.push(path4_crt);

        let path4_key = dir.join("device_512.key");
        fs::write(&path4_key, Self::to_pem("RSA PRIVATE KEY", &key4)).map_err(CarverError::Io)?;
        created.push(path4_key);

        let cert5 = Self::build_self_signed_cert();
        let path5 = dir.join("self_signed.pem");
        fs::write(&path5, Self::to_pem("CERTIFICATE", &cert5)).map_err(CarverError::Io)?;
        created.push(path5);

        Ok(created)
    }

    /// Build a raw firmware binary blob with embedded carved certificates and private keys.
    pub fn build_synthetic_firmware_cert_blob() -> Vec<u8> {
        let mut blob = Vec::new();
        // Bootloader prefix
        blob.extend_from_slice(b"U-BOOT-SPL-HEADER-BOOTLOADER-PAYLOAD-V1");
        blob.resize(512, 0x00);

        // Embedded DER certificate 1 (Expired)
        let expired_der = Self::build_expired_cert();
        blob.extend_from_slice(&expired_der);
        blob.resize(2048, 0xFF);

        // Embedded DER certificate 2 (Weak MD5)
        let md5_der = Self::build_weak_md5_cert();
        blob.extend_from_slice(&md5_der);
        blob.resize(4096, 0xAA);

        // Embedded PEM Key and Certificate pair
        let (weak_cert, weak_key) = Self::build_weak_rsa512_cert_and_key();
        let pem_cert = Self::to_pem("CERTIFICATE", &weak_cert);
        let pem_key = Self::to_pem("RSA PRIVATE KEY", &weak_key);
        blob.extend_from_slice(pem_cert.as_bytes());
        blob.extend_from_slice(b"\n");
        blob.extend_from_slice(pem_key.as_bytes());
        blob.resize(8192, 0x00);

        blob
    }
}

const OID_SHA256_WITH_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_MD5_WITH_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04];
const OID_SHA1_WITH_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
const OID_RSA_ENCRYPTION: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

fn make_dummy_modulus(byte_len: usize, fill: u8) -> Vec<u8> {
    let mut mod_bytes = vec![fill; byte_len];
    mod_bytes[0] = 0x81; // ensure high bit set
    mod_bytes[byte_len - 1] = 0x01; // ensure odd
    mod_bytes
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push((value.len() >> 8) as u8);
        out.push((value.len() & 0xFF) as u8);
    }
    out.extend_from_slice(value);
    out
}

fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(it);
    }
    der_tlv(0x30, &payload)
}

fn der_set(items: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(it);
    }
    der_tlv(0x31, &payload)
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut val = Vec::new();
    if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
        val.push(0x00);
    }
    val.extend_from_slice(bytes);
    der_tlv(0x02, &val)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut val = Vec::with_capacity(1 + bytes.len());
    val.push(0x00); // 0 unused bits
    val.extend_from_slice(bytes);
    der_tlv(0x03, &val)
}

fn build_dn(cn: &str, o: &str, c: &str) -> Vec<u8> {
    let atv_cn = der_sequence(&[
        &der_tlv(0x06, &[0x55, 0x04, 0x03]),
        &der_tlv(0x13, cn.as_bytes()),
    ]);
    let set_cn = der_set(&[&atv_cn]);

    let atv_o = der_sequence(&[
        &der_tlv(0x06, &[0x55, 0x04, 0x0A]),
        &der_tlv(0x13, o.as_bytes()),
    ]);
    let set_o = der_set(&[&atv_o]);

    let atv_c = der_sequence(&[
        &der_tlv(0x06, &[0x55, 0x04, 0x06]),
        &der_tlv(0x13, c.as_bytes()),
    ]);
    let set_c = der_set(&[&atv_c]);

    der_sequence(&[&set_c, &set_o, &set_cn])
}

fn parse_dn_fields(dn_str: &str) -> (String, String, String) {
    let mut cn = "Unknown".to_string();
    let mut o = "Unknown".to_string();
    let mut c = "US".to_string();
    for part in dn_str.split(',') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix("CN=") {
            cn = val.to_string();
        } else if let Some(val) = trimmed.strip_prefix("O=") {
            o = val.to_string();
        } else if let Some(val) = trimmed.strip_prefix("C=") {
            c = val.to_string();
        }
    }
    (cn, o, c)
}

fn build_cert_internal(
    subject_str: &str,
    issuer_str: &str,
    not_before_str: &str,
    not_after_str: &str,
    sig_oid: &[u8],
    rsa_modulus: &[u8],
) -> Vec<u8> {
    let serial = der_integer(&[0x01, 0x23, 0x45, 0x67]);
    let sig_algo = der_sequence(&[&der_tlv(0x06, sig_oid), &der_tlv(0x05, &[])]);

    let (s_cn, s_o, s_c) = parse_dn_fields(subject_str);
    let subject_dn = build_dn(&s_cn, &s_o, &s_c);

    let (i_cn, i_o, i_c) = parse_dn_fields(issuer_str);
    let issuer_dn = build_dn(&i_cn, &i_o, &i_c);

    let not_before_tag = if not_before_str.len() <= 13 {
        0x17
    } else {
        0x18
    };
    let not_after_tag = if not_after_str.len() <= 13 {
        0x17
    } else {
        0x18
    };
    let validity = der_sequence(&[
        &der_tlv(not_before_tag, not_before_str.as_bytes()),
        &der_tlv(not_after_tag, not_after_str.as_bytes()),
    ]);

    let rsa_pubkey_der = der_sequence(&[
        &der_integer(rsa_modulus),
        &der_integer(&[0x01, 0x00, 0x01]), // 65537
    ]);
    let spki = der_sequence(&[
        &der_sequence(&[&der_tlv(0x06, &OID_RSA_ENCRYPTION), &der_tlv(0x05, &[])]),
        &der_bit_string(&rsa_pubkey_der),
    ]);

    let tbs = der_sequence(&[
        &serial,
        &sig_algo,
        &issuer_dn,
        &validity,
        &subject_dn,
        &spki,
    ]);

    let dummy_signature = der_bit_string(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
    der_sequence(&[&tbs, &sig_algo, &dummy_signature])
}

fn build_rsa_private_key_der(modulus: &[u8]) -> Vec<u8> {
    let version = der_integer(&[0x00]);
    let n = der_integer(modulus);
    let e = der_integer(&[0x01, 0x00, 0x01]);
    let d = der_integer(&make_dummy_modulus(modulus.len(), 0x33));
    let p = der_integer(&make_dummy_modulus(modulus.len() / 2, 0x44));
    let q = der_integer(&make_dummy_modulus(modulus.len() / 2, 0x55));
    let dmp1 = der_integer(&make_dummy_modulus(modulus.len() / 2, 0x66));
    let dmq1 = der_integer(&make_dummy_modulus(modulus.len() / 2, 0x77));
    let iqmp = der_integer(&make_dummy_modulus(modulus.len() / 2, 0x88));

    der_sequence(&[&version, &n, &e, &d, &p, &q, &dmp1, &dmq1, &iqmp])
}
