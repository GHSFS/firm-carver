// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{EndpointKind, UrlScheme};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Candidate extracted token from text or binary payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedToken {
    pub raw: String,
    pub kind: EndpointKind,
    pub scheme: Option<UrlScheme>,
    pub host: String,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub credentials: Option<String>,
    pub offset: Option<usize>,
    pub line_number: Option<usize>,
}

/// Known binary, script, and image extensions to suppress false-positive domain matches.
const SUPPRESSED_EXTENSIONS: &[&str] = &[
    "so", "bin", "gz", "tar", "xz", "bz2", "zip", "png", "jpg", "jpeg", "gif", "html", "htm",
    "css", "js", "json", "xml", "sh", "py", "pl", "cgi", "conf", "cfg", "txt", "md", "c", "h", "o",
    "a", "ko", "dat", "bak", "log", "tmp", "lock", "pid", "patch", "diff", "orig",
];

/// Top-level or special-use domain suffixes recognized in embedded systems.
const VALID_TLDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "me", "cc", "tv", "info", "biz",
    "us", "uk", "de", "fr", "jp", "cn", "ru", "kr", "tw", "ca", "eu", "au", "ch", "se", "nl", "in",
    "br", "xyz", "app", "dev", "cloud", "online", "site", "live", "store", "tech", "local", "lan",
    "home", "internal", "corp", "test", "example", "invalid",
];

const SCHEMES: &[(&str, UrlScheme)] = &[
    ("http://", UrlScheme::Http),
    ("https://", UrlScheme::Https),
    ("ftp://", UrlScheme::Ftp),
    ("tftp://", UrlScheme::Tftp),
    ("telnet://", UrlScheme::Telnet),
    ("ws://", UrlScheme::Ws),
    ("wss://", UrlScheme::Wss),
    ("mqtt://", UrlScheme::Mqtt),
    ("mqtts://", UrlScheme::Mqtts),
];

/// Extract all valid network endpoints from a UTF-8 string or text line.
pub fn extract_endpoints_from_text(
    text: &str,
    base_offset: Option<usize>,
    line_number: Option<usize>,
) -> Vec<ExtractedToken> {
    let mut tokens = Vec::new();
    let lower_text = text.to_ascii_lowercase();
    let mut claimed_spans: Vec<(usize, usize)> = Vec::new();

    // 1. First pass: extract all full URLs
    for &(prefix, ref scheme) in SCHEMES {
        let mut search_idx = 0;
        while let Some(rel_idx) = lower_text[search_idx..].find(prefix) {
            let start = search_idx + rel_idx;
            // Scan to end of URL
            let mut end = start + prefix.len();
            let bytes = text.as_bytes();
            while end < bytes.len() && is_url_char(bytes[end]) {
                end += 1;
            }

            // Trim trailing punctuation that isn't part of the URL (e.g. '.', ',', ';', ')')
            let mut raw_url = &text[start..end];
            while raw_url.ends_with('.')
                || raw_url.ends_with(',')
                || raw_url.ends_with(';')
                || raw_url.ends_with(')')
                || raw_url.ends_with('>')
                || raw_url.ends_with('"')
                || raw_url.ends_with('\'')
            {
                raw_url = &raw_url[..raw_url.len() - 1];
                end -= 1;
            }

            if let Some(token) = parse_url_token(
                raw_url,
                scheme.clone(),
                base_offset.map(|o| o + start),
                line_number,
            ) {
                claimed_spans.push((start, end));
                tokens.push(token);
            }

            search_idx = end.max(start + prefix.len());
        }
    }

    // 2. Second pass: extract IPs and Domains from un-claimed regions
    let non_url_tokens = split_and_extract_non_url(text, &claimed_spans, base_offset, line_number);
    tokens.extend(non_url_tokens);

    tokens
}

fn is_url_char(b: u8) -> bool {
    b.is_ascii_graphic() && b != b'"' && b != b'\'' && b != b'`' && b != b'<' && b != b'>'
}

fn parse_url_token(
    raw: &str,
    scheme: UrlScheme,
    offset: Option<usize>,
    line_number: Option<usize>,
) -> Option<ExtractedToken> {
    let prefix_len = match &scheme {
        UrlScheme::Http => "http://".len(),
        UrlScheme::Https => "https://".len(),
        UrlScheme::Ftp => "ftp://".len(),
        UrlScheme::Tftp => "tftp://".len(),
        UrlScheme::Telnet => "telnet://".len(),
        UrlScheme::Ws => "ws://".len(),
        UrlScheme::Wss => "wss://".len(),
        UrlScheme::Mqtt => "mqtt://".len(),
        UrlScheme::Mqtts => "mqtts://".len(),
        UrlScheme::Other(s) => s.len() + 3,
    };

    if raw.len() <= prefix_len {
        return None;
    }

    let remainder = &raw[prefix_len..];
    let (auth, path) = match remainder.find('/') {
        Some(idx) => (&remainder[..idx], Some(remainder[idx..].to_string())),
        None => (remainder, None),
    };

    let (credentials, host_port) = match auth.find('@') {
        Some(idx) => (Some(auth[..idx].to_string()), &auth[idx + 1..]),
        None => (None, auth),
    };

    let (host, port) = parse_host_port(host_port);
    if host.is_empty() {
        return None;
    }

    Some(ExtractedToken {
        raw: raw.to_string(),
        kind: EndpointKind::Url,
        scheme: Some(scheme),
        host,
        port,
        path,
        credentials,
        offset,
        line_number,
    })
}

fn split_and_extract_non_url(
    text: &str,
    claimed_spans: &[(usize, usize)],
    base_offset: Option<usize>,
    line_number: Option<usize>,
) -> Vec<ExtractedToken> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut cursor = 0;

    while cursor < len {
        // Check if cursor is inside a claimed URL span
        let in_span = claimed_spans
            .iter()
            .find(|&&(s, e)| cursor >= s && cursor < e);
        if let Some(&(_, e)) = in_span {
            cursor = e;
            continue;
        }

        if is_token_delimiter(bytes[cursor]) {
            cursor += 1;
            continue;
        }

        let start = cursor;
        while cursor < len && !is_token_delimiter(bytes[cursor]) {
            if claimed_spans.iter().any(|&(s, _)| cursor == s) {
                break;
            }
            cursor += 1;
        }

        let word = &text[start..cursor];
        let trimmed = word
            .trim_matches(|c: char| "!\"'(),;<=>?[\\]^`{|}* \t\r\n".contains(c))
            .trim_end_matches('.');
        if !trimmed.is_empty() {
            let abs_offset = base_offset.map(|o| o + start);
            if let Some(t) = parse_ipv4_candidate(trimmed, abs_offset, line_number) {
                tokens.push(t);
            } else if let Some(t) = parse_ipv6_candidate(trimmed, abs_offset, line_number) {
                tokens.push(t);
            } else if let Some(t) = parse_domain_candidate(trimmed, abs_offset, line_number) {
                tokens.push(t);
            }
        }
    }

    tokens
}

fn is_token_delimiter(b: u8) -> bool {
    b.is_ascii_whitespace()
        || b == 0
        || b == b'='
        || b == b'"'
        || b == b'\''
        || b == b'`'
        || b == b'<'
        || b == b'>'
        || b == b'('
        || b == b')'
        || b == b'{'
        || b == b'}'
        || b == b'['
        || b == b']'
        || b == b';'
        || b == b','
        || b == b'|'
        || b == b'&'
        || b == b'!'
}

/// Extract printable ASCII strings from raw binary byte buffer.
pub fn extract_endpoints_from_binary(
    bytes: &[u8],
    min_length: usize,
    base_offset: usize,
) -> Vec<ExtractedToken> {
    let mut tokens = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_graphic() {
            let start = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_graphic() || bytes[cursor] == b' ')
            {
                cursor += 1;
            }
            let length = cursor - start;
            if length >= min_length {
                if let Ok(s) = std::str::from_utf8(&bytes[start..cursor]) {
                    let extracted = extract_endpoints_from_text(s, Some(base_offset + start), None);
                    tokens.extend(extracted);
                }
            }
        } else {
            cursor += 1;
        }
    }

    tokens
}

fn parse_host_port(host_port: &str) -> (String, Option<u16>) {
    if host_port.starts_with('[') {
        if let Some(end) = host_port.find(']') {
            let host = host_port[1..end].to_string();
            let port = if host_port.len() > end + 1 && host_port.as_bytes()[end + 1] == b':' {
                host_port[end + 2..].parse::<u16>().ok()
            } else {
                None
            };
            return (host, port);
        }
    }

    if let Some(idx) = host_port.rfind(':') {
        let host = &host_port[..idx];
        if let Ok(p) = host_port[idx + 1..].parse::<u16>() {
            return (host.to_string(), Some(p));
        }
    }

    (host_port.to_string(), None)
}

fn parse_ipv4_candidate(
    word: &str,
    offset: Option<usize>,
    line_number: Option<usize>,
) -> Option<ExtractedToken> {
    let (ip_str, port) = if let Some(idx) = word.find(':') {
        let port_candidate = word[idx + 1..].parse::<u16>().ok();
        (&word[..idx], port_candidate)
    } else {
        (word, None)
    };

    if let Ok(ipv4) = Ipv4Addr::from_str(ip_str) {
        let octets = ipv4.octets();
        if ip_str.split('.').count() == 4 && ip_str.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Some(ExtractedToken {
                raw: word.to_string(),
                kind: EndpointKind::Ipv4,
                scheme: None,
                host: format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
                port,
                path: None,
                credentials: None,
                offset,
                line_number,
            });
        }
    }
    None
}

fn parse_ipv6_candidate(
    word: &str,
    offset: Option<usize>,
    line_number: Option<usize>,
) -> Option<ExtractedToken> {
    let clean = word.trim_start_matches('[').trim_end_matches(']');
    if clean.contains(':') && clean.split(':').count() >= 3 {
        if let Ok(ipv6) = Ipv6Addr::from_str(clean) {
            return Some(ExtractedToken {
                raw: word.to_string(),
                kind: EndpointKind::Ipv6,
                scheme: None,
                host: ipv6.to_string(),
                port: None,
                path: None,
                credentials: None,
                offset,
                line_number,
            });
        }
    }
    None
}

fn parse_domain_candidate(
    word: &str,
    offset: Option<usize>,
    line_number: Option<usize>,
) -> Option<ExtractedToken> {
    let (domain_str, port) = if let Some(idx) = word.find(':') {
        let p = word[idx + 1..].parse::<u16>().ok();
        (&word[..idx], p)
    } else {
        (word, None)
    };

    if domain_str.len() < 3 || domain_str.len() > 253 {
        return None;
    }

    let labels: Vec<&str> = domain_str.split('.').collect();
    if labels.len() < 2 {
        return None;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }

    let tld = labels.last()?.to_ascii_lowercase();

    if SUPPRESSED_EXTENSIONS.contains(&tld.as_str()) {
        return None;
    }

    let is_valid_tld = VALID_TLDS.contains(&tld.as_str())
        || (tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()));
    if !is_valid_tld {
        return None;
    }

    if labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }

    Some(ExtractedToken {
        raw: word.to_string(),
        kind: EndpointKind::Domain,
        scheme: None,
        host: domain_str.to_ascii_lowercase(),
        port,
        path: None,
        credentials: None,
        offset,
        line_number,
    })
}
