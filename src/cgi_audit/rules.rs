// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{CgiFinding, CgiSeverity, CgiVulnCategory};

/// Rule evaluator that scans file lines and overall context for embedded web vulnerabilities.
pub struct CgiRuleEngine;

impl CgiRuleEngine {
    /// Evaluate all line-by-line static analysis rules for a single file.
    pub fn evaluate_lines(file_path: &str, content: &str) -> Vec<CgiFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (idx, raw_line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let line = raw_line.trim();

            // Skip pure comment lines in shell/lua/php/python/c
            if line.starts_with('#')
                || line.starts_with("//")
                || line.starts_with("--")
                || line.starts_with("/*")
                || line.starts_with('*')
            {
                continue;
            }

            let lower = line.to_ascii_lowercase();

            // Rule 1: CGI-CMD-001 - Shell evaluation of HTTP environment parameters
            if check_cmd_http_param(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-CMD-001-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-CMD-001".to_string(),
                    title: "Command Injection via HTTP Environment Variable".to_string(),
                    severity: CgiSeverity::Critical,
                    category: CgiVulnCategory::CommandInjection,
                    cwe: "CWE-78".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "User-controlled HTTP input ($QUERY_STRING, $POST_DATA, or HTTP header) is passed into shell command execution without sanitization.".to_string(),
                    remediation: "Avoid passing raw HTTP environment variables into shell interpreters. Validate all inputs against a strict whitelist or use parameterized APIs.".to_string(),
                });
            }

            // Rule 2: CGI-CMD-002 - Dangerous system command execution sinks
            if check_system_sink(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-CMD-002-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-CMD-002".to_string(),
                    title: "Dangerous System Execution Sink Invocation".to_string(),
                    severity: CgiSeverity::High,
                    category: CgiVulnCategory::CommandInjection,
                    cwe: "CWE-78".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "Process execution sink (system, popen, passthru, shell_exec) invoked. If arguments contain user parameters, this enables arbitrary code execution.".to_string(),
                    remediation: "Replace shell execution sinks with execve/posix_spawn with discrete argument vectors, avoiding sh -c parsing.".to_string(),
                });
            }

            // Rule 3: CGI-CMD-003 - GoAhead / Boa embedded webserver variable sinks
            if check_goahead_sink(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-CMD-003-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-CMD-003".to_string(),
                    title: "Embedded Webserver Variable Sink to System Function".to_string(),
                    severity: CgiSeverity::High,
                    category: CgiVulnCategory::CommandInjection,
                    cwe: "CWE-78".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "Embedded web engine variable getter (websGetVar, cgiFormString) observed adjacent to command formulation.".to_string(),
                    remediation: "Sanitize websGetVar outputs with character whitelists before passing to system commands.".to_string(),
                });
            }

            // Rule 4: CGI-AUTH-002 - Known backdoor authentication bypass headers / cookies
            if check_backdoor_auth(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-AUTH-002-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-AUTH-002".to_string(),
                    title: "Hardcoded Administrative Backdoor / Auth Bypass Cookie".to_string(),
                    severity: CgiSeverity::Critical,
                    category: CgiVulnCategory::AuthBypass,
                    cwe: "CWE-306".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "Backdoor cookie, magic parameter, or undocumented administrative bypass check detected in web logic.".to_string(),
                    remediation: "Remove undocumented bypass conditions and enforce uniform cryptographically signed session validation.".to_string(),
                });
            }

            // Rule 5: CGI-CRED-001 - Hardcoded default administrative credentials
            if check_hardcoded_credentials(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-CRED-001-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-CRED-001".to_string(),
                    title: "Hardcoded Administrative Credential Check".to_string(),
                    severity: CgiSeverity::High,
                    category: CgiVulnCategory::HardcodedCredentials,
                    cwe: "CWE-798".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "Static default credentials or hardcoded password strings embedded directly in web script authentication logic.".to_string(),
                    remediation: "Extract credentials to salted password hashes in /etc/shadow or enforce first-boot user password initialization.".to_string(),
                });
            }

            // Rule 6: CGI-TRAV-001 - Arbitrary path traversal / file read
            if check_path_traversal(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-TRAV-001-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-TRAV-001".to_string(),
                    title: "Potential Path Traversal / Arbitrary File Access".to_string(),
                    severity: CgiSeverity::High,
                    category: CgiVulnCategory::PathTraversal,
                    cwe: "CWE-22".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "File read or inclusion utility accesses path derived from user parameters without path normalization or basename extraction.".to_string(),
                    remediation: "Strip directory separators with basename, validate canonical realpath within allowed document root, and reject '..' segments.".to_string(),
                });
            }

            // Rule 7: CGI-INFO-001 - Sensitive file exposure (shadow, nvram, dmesg)
            if check_sensitive_info_exposure(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-INFO-001-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-INFO-001".to_string(),
                    title: "Sensitive System File or Diagnostic Exposure".to_string(),
                    severity: CgiSeverity::High,
                    category: CgiVulnCategory::InformationDisclosure,
                    cwe: "CWE-200".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "Direct read or output of sensitive system assets (/etc/shadow, /tmp/nvram, /dev/mtd, /proc/kmsg) through web endpoint.".to_string(),
                    remediation: "Never expose password hashes, raw NVRAM configurations, or partition dumps through unauthenticated web endpoints.".to_string(),
                });
            }

            // Rule 8: CGI-CONF-001 - Insecure debug daemon trigger
            if check_debug_daemon(&lower) {
                findings.push(CgiFinding {
                    id: format!("CGI-CONF-001-{}-L{}", sanitize_path_id(file_path), line_num),
                    rule_id: "CGI-CONF-001".to_string(),
                    title: "Unauthenticated Telnet / Debug Daemon Activation".to_string(),
                    severity: CgiSeverity::Critical,
                    category: CgiVulnCategory::InsecureConfiguration,
                    cwe: "CWE-16".to_string(),
                    file_path: file_path.to_string(),
                    line_number: Some(line_num),
                    evidence: truncate_evidence(line),
                    description: "Web script activates remote root shell daemons (telnetd, dropbear) or disables firewall filters via web trigger.".to_string(),
                    remediation: "Remove web-triggered debug backdoors and disable unauthenticated telnet activation scripts in production firmware.".to_string(),
                });
            }
        }

        findings
    }

    /// Evaluate file-wide architectural rules (such as unauthenticated administrative routes).
    pub fn evaluate_file_context(file_path: &str, content: &str) -> Vec<CgiFinding> {
        let mut findings = Vec::new();
        let lower = content.to_ascii_lowercase();

        // Check if file represents an administrative script
        let is_admin_script = is_administrative_script(file_path, &lower);

        if is_admin_script {
            let has_auth = has_authentication_guard(&lower);
            if !has_auth {
                findings.push(CgiFinding {
                    id: format!("CGI-AUTH-001-{}", sanitize_path_id(file_path)),
                    rule_id: "CGI-AUTH-001".to_string(),
                    title: "Unauthenticated Administrative Web Endpoint".to_string(),
                    severity: CgiSeverity::High,
                    category: CgiVulnCategory::AuthBypass,
                    cwe: "CWE-306".to_string(),
                    file_path: file_path.to_string(),
                    line_number: None,
                    evidence: format!("Script '{}' performs administrative actions without session or authentication verification.", file_path),
                    description: "Administrative actions (system reboot, configuration modification, firmware upgrade, diagnostic execution) detected without authentication guards.".to_string(),
                    remediation: "Enforce strict session token validation (e.g. check_session() or require_auth()) before processing any administrative request.".to_string(),
                });
            }
        }

        findings
    }
}

fn check_cmd_http_param(lower: &str) -> bool {
    let has_http_param = lower.contains("$query_string")
        || lower.contains("$post_data")
        || lower.contains("query_string")
        || lower.contains("http_cookie")
        || lower.contains("http_user_agent")
        || lower.contains("$_get[")
        || lower.contains("$_post[");

    if !has_http_param {
        return false;
    }

    lower.contains("eval ")
        || lower.contains("`")
        || lower.contains("$(")
        || lower.contains("ping ")
        || lower.contains("traceroute ")
        || lower.contains("cat ")
        || lower.contains("reboot")
        || lower.contains("iptables ")
        || lower.contains("system(")
        || lower.contains("popen(")
}

fn check_system_sink(lower: &str) -> bool {
    let has_sink = lower.contains("system(")
        || lower.contains("popen(")
        || lower.contains("passthru(")
        || lower.contains("shell_exec(")
        || lower.contains("io.popen(")
        || lower.contains("execve(")
        || lower.contains("execl(");

    if !has_sink {
        return false;
    }

    // Flag if variable or concatenation is inside
    lower.contains('$')
        || lower.contains('%')
        || lower.contains('+')
        || lower.contains(',')
        || lower.contains("query")
        || lower.contains("param")
        || lower.contains("getvar")
}

fn check_goahead_sink(lower: &str) -> bool {
    (lower.contains("websgetvar")
        || lower.contains("cgiformstring")
        || lower.contains("aspformprocess"))
        && (lower.contains("system")
            || lower.contains("eval")
            || lower.contains("sprintf")
            || lower.contains("exec"))
}

fn check_backdoor_auth(lower: &str) -> bool {
    lower.contains("dlink_uid")
        || lower.contains("gemtek_pass")
        || lower.contains("super_admin=1")
        || lower.contains("admin_bypass")
        || lower.contains("graphic_id=")
        || lower.contains("test_mode=1")
        || lower.contains("xmlset_setup.cgi")
}

fn check_hardcoded_credentials(lower: &str) -> bool {
    (lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("pwd")
        || lower.contains("pass"))
        && (lower.contains("\"admin\"")
            || lower.contains("'admin'")
            || lower.contains("\"123456\"")
            || lower.contains("'123456'")
            || lower.contains("\"password\"")
            || lower.contains("'password'")
            || lower.contains("\"root\"")
            || lower.contains("'root'"))
        && (lower.contains("==") || lower.contains(" = ") || lower.contains("eq "))
}

fn check_path_traversal(lower: &str) -> bool {
    (lower.contains("cat ")
        || lower.contains("readfile")
        || lower.contains("file_get_contents")
        || lower.contains("open("))
        && (lower.contains("$path")
            || lower.contains("$file")
            || lower.contains("$filename")
            || lower.contains("$_get")
            || lower.contains("$_post")
            || lower.contains("../")
            || lower.contains("..\\"))
        && !lower.contains("basename")
}

fn check_sensitive_info_exposure(lower: &str) -> bool {
    (lower.contains("/etc/shadow")
        || lower.contains("/tmp/nvram")
        || lower.contains("/dev/mtd")
        || lower.contains("/proc/kmsg"))
        && (lower.contains("cat ")
            || lower.contains("echo ")
            || lower.contains("print")
            || lower.contains("read")
            || lower.contains("tar ")
            || lower.contains("cp "))
}

fn check_debug_daemon(lower: &str) -> bool {
    (lower.contains("telnetd") && (lower.contains("-l /bin/sh") || lower.contains("-p ")))
        || (lower.contains("dropbear") && lower.contains("-b"))
        || (lower.contains("iptables -f") || lower.contains("iptables --flush"))
}

fn is_administrative_script(file_path: &str, lower: &str) -> bool {
    let path_lower = file_path.to_ascii_lowercase();

    // Filename indicators of administrative operations
    let name_indicates_admin = path_lower.contains("apply")
        || path_lower.contains("reboot")
        || path_lower.contains("upgrade")
        || path_lower.contains("backup")
        || path_lower.contains("restore")
        || path_lower.contains("factory")
        || path_lower.contains("passwd")
        || path_lower.contains("tools_")
        || path_lower.contains("system.cgi");

    // Action indicators within script content
    let content_indicates_admin = lower.contains("reboot")
        || lower.contains("mtd write")
        || lower.contains("flash write")
        || lower.contains("nvram commit")
        || lower.contains("factory_reset")
        || lower.contains("killall -9")
        || lower.contains("sysupgrade");

    name_indicates_admin || content_indicates_admin
}

fn has_authentication_guard(lower: &str) -> bool {
    lower.contains("check_auth")
        || lower.contains("check_login")
        || lower.contains("is_authenticated")
        || lower.contains("is_logged_in")
        || lower.contains("auth_check")
        || lower.contains("require_auth")
        || lower.contains("require_login")
        || lower.contains("check_session")
        || lower.contains("check_cookie")
        || lower.contains("verify_session")
        || lower.contains("session_id")
        || lower.contains("luci.dispatcher.require_auth")
        || lower.contains("http_auth")
}

fn sanitize_path_id(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn truncate_evidence(evidence: &str) -> String {
    if evidence.len() > 100 {
        format!("{}...", &evidence[..100])
    } else {
        evidence.to_string()
    }
}
