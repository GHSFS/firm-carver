// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::decompress::{decompress_file_blocks, decompress_symlink_target};
use super::superblock::unpack_inode;
use super::types::{
    CramFsEntry, CramFsFileType, CramFsSummary, CramFsSuperblock, S_IFDIR, S_IFLNK, S_IFMT,
    S_ISGID, S_ISUID, S_ISVTX,
};
use crate::error::{CarverError, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const CRAMFS_MAX_DIR_DEPTH: usize = 32;

pub fn format_mode_string(mode: u16) -> String {
    let file_char = match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };

    let r1 = if mode & 0o400 != 0 { 'r' } else { '-' };
    let w1 = if mode & 0o200 != 0 { 'w' } else { '-' };
    let x1 = match (mode & 0o100 != 0, mode & S_ISUID != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    };

    let r2 = if mode & 0o040 != 0 { 'r' } else { '-' };
    let w2 = if mode & 0o020 != 0 { 'w' } else { '-' };
    let x2 = match (mode & 0o010 != 0, mode & S_ISGID != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    };

    let r3 = if mode & 0o004 != 0 { 'r' } else { '-' };
    let w3 = if mode & 0o002 != 0 { 'w' } else { '-' };
    let x3 = match (mode & 0o001 != 0, mode & S_ISVTX != 0) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        (false, false) => '-',
    };

    format!(
        "{}{}{}{}{}{}{}{}{}{}",
        file_char, r1, w1, x1, r2, w2, x2, r3, w3, x3
    )
}

pub fn walk_directory_tree(
    data: &[u8],
    superblock: &CramFsSuperblock,
) -> Result<(Vec<CramFsEntry>, CramFsSummary)> {
    let mut entries = Vec::new();
    let mut visited_offsets = HashSet::new();

    let root_offset = (superblock.root.offset as usize) << 2;
    let actual_root_offset = if root_offset == 0 {
        if data.len() >= 512 && detect_dir_header_candidate(&data[512..]) {
            512
        } else if data.len() >= 64 && detect_dir_header_candidate(&data[64..]) {
            64
        } else {
            0
        }
    } else {
        root_offset
    };

    if actual_root_offset > 0 && actual_root_offset < data.len() && superblock.root.size > 0 {
        walk_dir_recursive(
            data,
            actual_root_offset,
            superblock.root.size as usize,
            "",
            0,
            superblock,
            &mut visited_offsets,
            &mut entries,
        )?;
    }

    let mut known_paths = HashSet::new();
    for e in &entries {
        known_paths.insert(e.path.clone());
    }

    let mut summary = CramFsSummary {
        total_entries: entries.len(),
        ..Default::default()
    };

    for e in entries.iter_mut() {
        match e.file_type {
            CramFsFileType::Directory => summary.directories += 1,
            CramFsFileType::RegularFile => {
                summary.regular_files += 1;
                summary.total_uncompressed_bytes += e.size;
            }
            CramFsFileType::Symlink => {
                summary.symlinks += 1;
                if let Some(target) = &e.symlink_target {
                    if is_traversal_target(target) {
                        e.is_path_traversal = true;
                        summary.traversal_symlinks_count += 1;
                    }
                    if is_dangling_target(&e.path, target, &known_paths) {
                        e.is_dangling_symlink = true;
                        summary.dangling_symlinks_count += 1;
                    }
                }
            }
            _ => summary.special_nodes += 1,
        }

        if e.mode & S_ISUID != 0 || e.mode & S_ISGID != 0 {
            summary.suid_files_count += 1;
        }
    }

    Ok((entries, summary))
}

fn detect_dir_header_candidate(slice: &[u8]) -> bool {
    if slice.len() < 12 {
        return false;
    }
    let namelen = (slice[8] & 0x3F) as usize;
    namelen > 0 && namelen <= 63
}

#[allow(clippy::too_many_arguments)]
fn walk_dir_recursive(
    data: &[u8],
    dir_offset: usize,
    dir_size: usize,
    parent_path: &str,
    depth: usize,
    superblock: &CramFsSuperblock,
    visited_offsets: &mut HashSet<usize>,
    entries: &mut Vec<CramFsEntry>,
) -> Result<()> {
    if depth > CRAMFS_MAX_DIR_DEPTH {
        return Ok(());
    }

    if !visited_offsets.insert(dir_offset) {
        return Ok(());
    }

    let dir_end = dir_offset.saturating_add(dir_size).min(data.len());
    let mut cur_offset = dir_offset;

    while cur_offset + 12 <= dir_end {
        let inode = match unpack_inode(&data[cur_offset..cur_offset + 12], superblock.endianness) {
            Ok(ino) => ino,
            Err(_) => break,
        };

        let namelen_bytes = (inode.namelen as usize) << 2;
        if namelen_bytes == 0 || cur_offset + 12 + namelen_bytes > data.len() {
            break;
        }

        let name_slice = &data[cur_offset + 12..cur_offset + 12 + namelen_bytes];
        let name_clean = name_slice.split(|&b| b == 0).next().unwrap_or(name_slice);
        let name_str = String::from_utf8_lossy(name_clean).to_string();

        if name_str.is_empty() {
            cur_offset += 12 + namelen_bytes;
            continue;
        }

        let entry_path = if parent_path.is_empty() {
            format!("/{}", name_str)
        } else {
            format!("{}/{}", parent_path, name_str)
        };

        let file_type = CramFsFileType::from_mode(inode.mode);
        let payload_byte_offset = (inode.offset as usize) << 2;

        let mut symlink_target = None;
        let is_path_traversal =
            name_str.contains('/') || name_str.contains("..") || name_str.starts_with("../");

        if file_type == CramFsFileType::Symlink && payload_byte_offset < data.len() {
            if let Ok(target) = decompress_symlink_target(
                data,
                payload_byte_offset,
                inode.size as usize,
                superblock.endianness,
                superblock.flags,
            ) {
                symlink_target = Some(target);
            }
        }

        let entry = CramFsEntry {
            path: entry_path.clone(),
            name: name_str,
            file_type,
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size as usize,
            offset: cur_offset,
            payload_offset: payload_byte_offset,
            symlink_target,
            is_dangling_symlink: false,
            is_path_traversal,
        };

        entries.push(entry);

        if file_type == CramFsFileType::Directory
            && inode.size > 0
            && payload_byte_offset > 0
            && payload_byte_offset < data.len()
        {
            walk_dir_recursive(
                data,
                payload_byte_offset,
                inode.size as usize,
                &entry_path,
                depth + 1,
                superblock,
                visited_offsets,
                entries,
            )?;
        }

        cur_offset += 12 + namelen_bytes;
    }

    Ok(())
}

fn is_traversal_target(target: &str) -> bool {
    target.contains("../")
        || target.starts_with('/')
            && (target.starts_with("/etc/")
                || target.starts_with("/root/")
                || target.starts_with("/sys/")
                || target.starts_with("/proc/")
                || target.starts_with("/dev/")
                || target.starts_with("/var/run/"))
}

fn is_dangling_target(symlink_path: &str, target: &str, known_paths: &HashSet<String>) -> bool {
    let resolved = if target.starts_with('/') {
        target.to_string()
    } else {
        let parent = Path::new(symlink_path).parent().unwrap_or(Path::new("/"));
        let joined = parent.join(target);
        normalize_path(&joined)
    };

    !known_paths.contains(&resolved)
}

fn normalize_path(path: &Path) -> String {
    let mut stack = Vec::new();
    for comp in path.components() {
        match comp {
            Component::Normal(c) => stack.push(c.to_string_lossy().to_string()),
            Component::ParentDir => {
                stack.pop();
            }
            _ => {}
        }
    }
    format!("/{}", stack.join("/"))
}

pub fn validate_safe_path(base_dir: &Path, rel_path: &str) -> Result<PathBuf> {
    let clean_rel = rel_path.trim_start_matches('/');
    let target = base_dir.join(clean_rel);

    let mut depth: isize = 0;
    for component in Path::new(clean_rel).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => depth -= 1,
            Component::CurDir => {}
            _ => {
                return Err(CarverError::ExtractionFailed(format!(
                    "Illegal path component in '{}'",
                    rel_path
                )));
            }
        }
        if depth < 0 {
            return Err(CarverError::ExtractionFailed(format!(
                "Path traversal detected escaping target directory: '{}'",
                rel_path
            )));
        }
    }

    Ok(target)
}

pub fn extract_archive_to_disk(
    data: &[u8],
    entries: &[CramFsEntry],
    superblock: &CramFsSuperblock,
    out_dir: &Path,
) -> Result<usize> {
    fs::create_dir_all(out_dir)?;
    let mut extracted_count = 0;

    for entry in entries {
        let dest = validate_safe_path(out_dir, &entry.path)?;

        match entry.file_type {
            CramFsFileType::Directory => {
                fs::create_dir_all(&dest)?;
                extracted_count += 1;
            }
            CramFsFileType::RegularFile => {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                let content = decompress_file_blocks(
                    data,
                    entry.payload_offset,
                    entry.size,
                    superblock.endianness,
                    superblock.flags,
                )
                .unwrap_or_default();

                fs::write(&dest, &content)?;
                extracted_count += 1;
            }
            CramFsFileType::Symlink => {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                if let Some(target) = &entry.symlink_target {
                    #[cfg(windows)]
                    {
                        let _ = fs::write(&dest, format!("SYMLINK: {}", target));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        let _ = symlink(target, &dest);
                    }
                    extracted_count += 1;
                }
            }
            _ => {}
        }
    }

    Ok(extracted_count)
}
