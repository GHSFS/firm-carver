// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod arch_detect;
pub mod audit;
pub mod carve;
pub mod cert_audit;
pub mod cgi_audit;
pub mod common;
pub mod cramfs;
pub mod domain_audit;
pub mod fdt;
pub mod inspect;
pub mod integrity;
pub mod jffs2;
pub mod nvram;
pub mod slice;
pub mod squashfs;
pub mod synth_fw;
pub mod ubifs;

use firm_carver::cli::{Cli, Commands};
use firm_carver::error::Result;

pub fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Inspect(args) => inspect::handle_inspect(args),
        Commands::Carve(args) => carve::handle_carve(args),
        Commands::Audit(args) => audit::handle_audit(args),
        Commands::Squashfs(args) => squashfs::handle_squashfs(args),
        Commands::Cramfs(args) => cramfs::handle_cramfs(args),
        Commands::Jffs2(args) => jffs2::handle_jffs2(args),
        Commands::Ubifs(args) => ubifs::handle_ubifs(args),
        Commands::Fdt(args) => fdt::handle_fdt(args),
        Commands::ArchDetect(args) => arch_detect::handle_arch_detect(args),
        Commands::Slice(args) => slice::handle_slice(args),
        Commands::Integrity(args) => integrity::handle_integrity(args),
        Commands::CgiAudit(args) => cgi_audit::handle_cgi_audit(args),
        Commands::CertAudit(args) => cert_audit::handle_cert_audit(args),
        Commands::Nvram(args) => nvram::handle_nvram(args),
        Commands::DomainAudit(args) => domain_audit::handle_domain_audit(args),
        Commands::SynthFw(args) => synth_fw::handle_synth_fw(args),
    }
}
