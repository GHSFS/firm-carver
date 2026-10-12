// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::fdt::{build_synthetic_fdt, DtBuilder, FdtArchive, FdtHeader, FDT_MAGIC};

#[test]
fn test_fdt_synthetic_blob_generation_and_header_parsing() {
    let dtb = build_synthetic_fdt();
    assert!(dtb.len() >= 40);

    let header = FdtHeader::parse(&dtb).expect("Failed to parse valid synthetic FDT header");
    assert_eq!(header.magic, FDT_MAGIC);
    assert_eq!(header.totalsize as usize, dtb.len());
    assert_eq!(header.version, 17);
    assert_eq!(header.last_comp_version, 16);

    let reservations = header
        .parse_mem_rsvmap(&dtb)
        .expect("Failed to parse memory reservation map");
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].address, 0x8000_0000);
    assert_eq!(reservations[0].size, 0x0001_0000);
}

#[test]
fn test_fdt_full_tree_disassembly_and_dts_syntax() {
    let dtb = build_synthetic_fdt();
    let archive = FdtArchive::parse(&dtb).expect("Failed to parse FDT archive");

    let dts = archive.format_dts();
    assert!(dts.contains("/dts-v1/;"));
    assert!(dts.contains("/memreserve/ 0x80000000 0x00010000;"));
    assert!(dts.contains("model = \"GHSFS Industrial Gateway AX-3000\";"));
    assert!(dts.contains("compatible = \"ghsfs,ax3000\", \"qcom,ipq8074\";"));
    assert!(dts.contains("chosen {"));
    assert!(dts.contains(
        "bootargs = \"console=ttyMSM0,115200 root=/dev/mtdblock4 rootfstype=squashfs ro\";"
    ));
    assert!(dts.contains("stdout-path = \"/soc/serial@18000000:115200\";"));
    assert!(dts.contains("memory@80000000 {"));
    assert!(dts.contains("reg = <0x80000000 0x10000000>;"));
    assert!(dts.contains("serial@18000000 {"));
    assert!(dts.contains("compatible = \"qcom,msm-uart\", \"ns16550a\";"));
    assert!(dts.contains("partition@0 {"));
    assert!(dts.contains("label = \"u-boot\";"));
    assert!(dts.contains("read-only;"));
    assert!(dts.contains("ethernet@18080000 {"));
    assert!(dts.contains("local-mac-address = [00 a0 c6 eb 12 34];"));
}

#[test]
fn test_fdt_hardware_peripheral_mapping() {
    let dtb = build_synthetic_fdt();
    let archive = FdtArchive::parse(&dtb).expect("Failed to parse FDT archive");
    let hw = &archive.hardware;

    // Board & Chosen
    assert_eq!(
        hw.model.as_deref(),
        Some("GHSFS Industrial Gateway AX-3000")
    );
    assert_eq!(hw.compatible, vec!["ghsfs,ax3000", "qcom,ipq8074"]);
    assert!(hw
        .bootargs
        .as_ref()
        .unwrap()
        .contains("console=ttyMSM0,115200"));
    assert_eq!(
        hw.stdout_path.as_deref(),
        Some("/soc/serial@18000000:115200")
    );

    // RAM
    assert_eq!(hw.memory_ranges.len(), 1);
    assert_eq!(hw.memory_ranges[0].base, 0x8000_0000);
    assert_eq!(hw.memory_ranges[0].size, 0x1000_0000); // 256 MB
    assert_eq!(hw.memory_reservations.len(), 1);

    // UART Console
    assert_eq!(hw.uart_consoles.len(), 1);
    let uart = &hw.uart_consoles[0];
    assert_eq!(uart.node_name, "serial@18000000");
    assert_eq!(uart.base_address, Some(0x1800_0000));
    assert_eq!(uart.reg_size, Some(0x1000));
    assert_eq!(uart.interrupts, Some(vec![0, 24, 4]));
    assert!(uart.is_active_console);

    // Flash Partitions
    assert_eq!(hw.flash_partitions.len(), 5);
    assert_eq!(hw.flash_partitions[0].label, "u-boot");
    assert_eq!(hw.flash_partitions[0].offset, 0x0000_0000);
    assert_eq!(hw.flash_partitions[0].size, 0x0008_0000);
    assert!(hw.flash_partitions[0].read_only);

    assert_eq!(hw.flash_partitions[1].label, "u-boot-env");
    assert_eq!(hw.flash_partitions[1].offset, 0x0008_0000);
    assert!(!hw.flash_partitions[1].read_only);

    assert_eq!(hw.flash_partitions[2].label, "kernel");
    assert_eq!(hw.flash_partitions[2].offset, 0x000C_0000);
    assert_eq!(hw.flash_partitions[2].size, 0x0040_0000);

    assert_eq!(hw.flash_partitions[3].label, "rootfs");
    assert_eq!(hw.flash_partitions[3].offset, 0x004C_0000);
    assert_eq!(hw.flash_partitions[3].size, 0x00B0_0000);

    assert_eq!(hw.flash_partitions[4].label, "art");
    assert_eq!(hw.flash_partitions[4].offset, 0x00FC_0000);
    assert_eq!(hw.flash_partitions[4].size, 0x0004_0000);
    assert!(hw.flash_partitions[4].read_only);

    // Network Interface
    assert_eq!(hw.network_interfaces.len(), 1);
    let net = &hw.network_interfaces[0];
    assert_eq!(net.node_name, "ethernet@18080000");
    assert_eq!(net.mac_address.as_deref(), Some("00:A0:C6:EB:12:34"));
    assert_eq!(net.phy_mode.as_deref(), Some("rgmii"));

    // CPUs
    assert_eq!(hw.cpus.len(), 1);
    assert_eq!(hw.cpus[0].name, "cpu@0");
    assert_eq!(hw.cpus[0].compatible.as_deref(), Some("arm,cortex-a53"));
    assert_eq!(hw.cpus[0].clock_frequency, Some(1_400_000_000));
}

#[test]
fn test_fdt_hardware_summary_formatting() {
    let dtb = build_synthetic_fdt();
    let archive = FdtArchive::parse(&dtb).expect("Failed to parse FDT archive");
    let summary = archive.format_hardware_summary();

    assert!(summary.contains("=== FirmCarver Hardware Peripheral Map ==="));
    assert!(summary.contains("Board Model:         GHSFS Industrial Gateway AX-3000"));
    assert!(summary.contains("0x80000000 - 0x90000000 (256 MB)"));
    assert!(summary.contains("serial@18000000"));
    assert!(summary.contains("u-boot"));
    assert!(summary.contains("[read-only]"));
    assert!(summary.contains("rootfs"));
    assert!(summary.contains("[read-write]"));
    assert!(summary.contains("00:A0:C6:EB:12:34"));
    assert!(summary.contains("cpu@0"));
}

#[test]
fn test_fdt_corrupted_inputs_and_bounds_guards() {
    // Empty buffer
    assert!(FdtArchive::parse(&[]).is_err());

    // Truncated header
    assert!(FdtArchive::parse(&[0xD0, 0x0D, 0xFE, 0xED, 0x00]).is_err());

    // Invalid magic bytes
    let mut bad_magic = build_synthetic_fdt();
    bad_magic[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(FdtArchive::parse(&bad_magic).is_err());

    // Totalsize exceeds actual buffer length
    let mut bad_size = build_synthetic_fdt();
    bad_size[4..8].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
    assert!(FdtArchive::parse(&bad_size).is_err());

    // Corrupted token in struct block
    let mut bad_token = build_synthetic_fdt();
    let header = FdtHeader::parse(&bad_token).unwrap();
    let off = header.off_dt_struct as usize;
    bad_token[off..off + 4].copy_from_slice(&0xEEEE_EEEEu32.to_be_bytes());
    assert!(FdtArchive::parse(&bad_token).is_err());
}

#[test]
fn test_fdt_embedded_stream_offset_parsing() {
    let dtb = build_synthetic_fdt();
    let mut padded_blob = Vec::new();
    padded_blob.resize(0x2000, 0x55); // Pre-padding
    let offset = padded_blob.len();
    padded_blob.extend_from_slice(&dtb);
    padded_blob.resize(offset + dtb.len() + 0x1000, 0xAA); // Post-padding

    // Parse at explicit offset
    let archive =
        FdtArchive::parse(&padded_blob[offset..]).expect("Failed to parse at stream offset");
    assert_eq!(
        archive.hardware.model.as_deref(),
        Some("GHSFS Industrial Gateway AX-3000")
    );
    assert_eq!(archive.hardware.flash_partitions.len(), 5);
}

#[test]
fn test_fdt_custom_builder_minimal_tree() {
    let mut builder = DtBuilder::new();
    builder.begin_node("");
    builder.add_prop_string("model", "Minimal Test Board");
    builder.add_prop_empty("custom-flag");
    builder.add_prop_u32_array("reg-pair", &[0x1000, 0x2000]);

    builder.begin_node("subsystem@1000");
    builder.add_prop_string("status", "okay");
    builder.end_node();

    builder.end_node();

    let custom_blob = builder.build(&[(0x1000_0000, 0x4000)]);
    let archive = FdtArchive::parse(&custom_blob).expect("Failed to parse custom DTB");

    assert_eq!(
        archive.hardware.model.as_deref(),
        Some("Minimal Test Board")
    );
    assert_eq!(archive.mem_rsvmap.len(), 1);
    assert_eq!(archive.mem_rsvmap[0].address, 0x1000_0000);
    assert_eq!(archive.mem_rsvmap[0].size, 0x4000);

    let dts = archive.format_dts();
    assert!(dts.contains("custom-flag;"));
    assert!(dts.contains("subsystem@1000 {"));
}
