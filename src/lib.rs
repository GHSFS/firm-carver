// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod carve;
pub mod cli;
pub mod error;
pub mod image;
pub mod vuln_scan;

pub use carve::{
    carve_and_extract, scan_carvable_streams, CarveManifest, CarvedKind, CarvedSegment,
};
pub use error::{CarverError, Result};
pub use image::{
    build_synthetic_firmware, compute_crc32, scan_containers, ContainerKind, ContainerMetadata,
    DiscoveredContainer,
};
pub use vuln_scan::{
    scan_vulnerabilities, VulnAuditReport, VulnCategory, VulnFinding, VulnSeverity,
};
