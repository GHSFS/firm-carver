// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Deterministic generator of synthetic web management interfaces and vulnerable CGI scripts.
pub struct CgiSynth;

impl CgiSynth {
    /// Generate a structured list of in-memory files `(relative_path, script_content)` representing
    /// a realistic embedded router `/www` directory containing known security weaknesses.
    pub fn build_synthetic_web_tree() -> Vec<(String, String)> {
        vec![
            // 1. Diagnostic ping with command injection via QUERY_STRING
            (
                "cgi-bin/ping.cgi".to_string(),
                r#"#!/bin/sh
echo "Content-type: text/html"
echo ""
echo "<html><body><h2>Network Ping Diagnostic</h2>"
HOST=$(echo "$QUERY_STRING" | cut -d'=' -f2)
echo "<pre>"
ping -c 2 $HOST
echo "</pre></body></html>"
"#
                .to_string(),
            ),
            // 2. Sensitive information disclosure exposing /tmp/nvram and /proc/kmsg
            (
                "cgi-bin/status.cgi".to_string(),
                r#"#!/bin/sh
echo "Content-type: text/plain"
echo ""
echo "=== System Diagnostic Info ==="
cat /proc/kmsg
cat /tmp/nvram
"#
                .to_string(),
            ),
            // 3. Unauthenticated administrative reboot endpoint with D-Link backdoor cookie
            (
                "apply.cgi".to_string(),
                r#"#!/bin/sh
echo "Content-type: text/plain"
echo ""
# Backdoor override check
if echo "$HTTP_COOKIE" | grep -q "dlink_uid=0"; then
    echo "Administrative override accepted"
    reboot
    exit 0
fi

ACTION="$QUERY_STRING"
if [ "$ACTION" = "reboot" ]; then
    reboot
fi
"#
                .to_string(),
            ),
            // 4. Hardcoded administrative credentials check in web script
            (
                "login.cgi".to_string(),
                r#"#!/bin/sh
echo "Content-type: text/plain"
echo ""
USERNAME="admin"
PASSWORD="password"

if [ "$USER" = "$USERNAME" ] && [ "$PASS" == "admin" ]; then
    echo "Login successful"
else
    echo "Login failed"
fi
"#
                .to_string(),
            ),
            // 5. Path traversal in file viewer utility
            (
                "view.cgi".to_string(),
                r#"#!/bin/sh
echo "Content-type: text/plain"
echo ""
TARGET_FILE=$(echo "$QUERY_STRING" | cut -d'=' -f2)
cat /www/data/$TARGET_FILE
"#
                .to_string(),
            ),
            // 6. Web triggered telnet root backdoor daemon
            (
                "tools_debug.cgi".to_string(),
                r#"#!/bin/sh
echo "Content-type: text/plain"
echo ""
echo "Enabling factory debug mode..."
telnetd -l /bin/sh -p 2323
"#
                .to_string(),
            ),
            // 7. Secure administrative script that validates authentication
            (
                "secure_settings.cgi".to_string(),
                r#"#!/bin/sh
echo "Content-type: text/plain"
echo ""
# Strict session check
check_auth || exit 1

echo "Authenticated administrative settings updated."
"#
                .to_string(),
            ),
            // 8. Safe static landing page
            (
                "index.html".to_string(),
                r#"<!DOCTYPE html>
<html>
<head><title>Embedded Router Web Management</title></head>
<body>
<h1>Router Configuration Portal</h1>
<p>Please enter administrative credentials to continue.</p>
</body>
</html>
"#
                .to_string(),
            ),
        ]
    }

    /// Write synthetic web management directory tree to target path on disk.
    pub fn write_synthetic_web_tree_to_disk(base_dir: &Path) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(base_dir).map_err(CarverError::Io)?;
        let mut created = Vec::new();

        for (rel_path, content) in Self::build_synthetic_web_tree() {
            let full_path = base_dir.join(&rel_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent).map_err(CarverError::Io)?;
            }

            fs::write(&full_path, content.as_bytes()).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to write synthetic CGI {}: {}",
                        full_path.display(),
                        e
                    ),
                ))
            })?;

            created.push(full_path);
        }

        Ok(created)
    }

    /// Build a single synthetic firmware blob containing embedded CGI script strings.
    pub fn build_synthetic_firmware_with_cgi() -> Vec<u8> {
        let mut blob = Vec::new();
        // Container header prefix
        blob.extend_from_slice(b"UBOOT_HEADER_FAKE_0x27051956");
        blob.resize(64, 0);

        // Embedded web interface scripts
        for (path, content) in Self::build_synthetic_web_tree() {
            blob.extend_from_slice(format!("\n=== FILE: {} ===\n", path).as_bytes());
            blob.extend_from_slice(content.as_bytes());
            blob.push(0);
        }

        // Padding to realistic partition boundary
        let remainder = blob.len() % 512;
        if remainder != 0 {
            blob.resize(blob.len() + (512 - remainder), 0xFF);
        }

        blob
    }
}
