// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::inode::{parse_inode, read_inode_content};
use super::superblock::{read_u16, read_u32};
use super::types::*;
use crate::error::{CarverError, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const EXT_ROOT_INO: u32 = 2;
pub const MAX_DIRECTORY_RECURSION_DEPTH: usize = 32;

#[derive(Debug, Clone)]
pub struct RawDirEntry {
    pub ino: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    pub name: String,
}

pub fn parse_directory_block(block_data: &[u8], endian: Endianness) -> Vec<RawDirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + 8 <= block_data.len() {
        let ino = match read_u32(block_data, offset, endian) {
            Ok(val) => val,
            Err(_) => break,
        };
        let rec_len = match read_u16(block_data, offset + 4, endian) {
            Ok(val) => val,
            Err(_) => break,
        };
        if rec_len < 8 || (offset + (rec_len as usize)) > block_data.len() {
            break;
        }

        let name_len = block_data[offset + 6];
        let file_type = block_data[offset + 7];

        if ino != 0
            && name_len > 0
            && offset + 8 + (name_len as usize) <= offset + (rec_len as usize)
        {
            let name_bytes = &block_data[offset + 8..offset + 8 + (name_len as usize)];
            let name = String::from_utf8_lossy(name_bytes).to_string();
            entries.push(RawDirEntry {
                ino,
                rec_len,
                name_len,
                file_type,
                name,
            });
        }

        offset += rec_len as usize;
    }

    entries
}

pub fn reconstruct_filesystem(
    data: &[u8],
    base_offset: usize,
    sb: &ExtSuperblock,
    groups: &[BlockGroupDescriptor],
) -> Result<(Vec<ExtEntry>, ExtSummary)> {
    let mut entries = Vec::new();
    let mut visited_inodes = HashSet::new();

    let root_inode = parse_inode(data, base_offset, sb, groups, EXT_ROOT_INO)?;
    entries.push(ExtEntry {
        ino: EXT_ROOT_INO,
        path: "/".to_string(),
        name: "/".to_string(),
        parent_ino: EXT_ROOT_INO,
        file_type: ExtFileType::Directory,
        mode: root_inode.mode,
        uid: root_inode.uid,
        gid: root_inode.gid,
        size: root_inode.size,
        symlink_target: None,
        mtime: root_inode.mtime,
    });
    visited_inodes.insert(EXT_ROOT_INO);

    walk_directory_recursive(
        data,
        base_offset,
        sb,
        groups,
        &root_inode,
        "/",
        0,
        &mut visited_inodes,
        &mut entries,
    )?;

    // Calculate Summary
    let mut regular_files = 0;
    let mut directories = 0;
    let mut symlinks = 0;
    let mut special_files = 0;
    let mut total_bytes = 0u64;

    for e in &entries {
        match e.file_type {
            ExtFileType::RegularFile => {
                regular_files += 1;
                total_bytes += e.size;
            }
            ExtFileType::Directory => directories += 1,
            ExtFileType::Symlink => symlinks += 1,
            _ => special_files += 1,
        }
    }

    let summary = ExtSummary {
        total_entries: entries.len(),
        regular_files,
        directories,
        symlinks,
        special_files,
        total_bytes,
    };

    Ok((entries, summary))
}

#[allow(clippy::too_many_arguments)]
fn walk_directory_recursive(
    data: &[u8],
    base_offset: usize,
    sb: &ExtSuperblock,
    groups: &[BlockGroupDescriptor],
    dir_inode: &ExtInode,
    current_path: &str,
    depth: usize,
    visited_inodes: &mut HashSet<u32>,
    out_entries: &mut Vec<ExtEntry>,
) -> Result<()> {
    if depth >= MAX_DIRECTORY_RECURSION_DEPTH {
        return Ok(());
    }

    let dir_payload = read_inode_content(data, base_offset, sb, groups, dir_inode)?;
    let raw_entries = parse_directory_block(&dir_payload, sb.endianness);

    for raw in raw_entries {
        if raw.name == "." || raw.name == ".." {
            continue;
        }

        let child_path = if current_path == "/" {
            format!("/{}", raw.name)
        } else {
            format!("{}/{}", current_path, raw.name)
        };

        if visited_inodes.contains(&raw.ino) {
            continue;
        }

        let child_inode = match parse_inode(data, base_offset, sb, groups, raw.ino) {
            Ok(node) => node,
            Err(_) => continue,
        };

        visited_inodes.insert(raw.ino);

        let mut symlink_target = child_inode.symlink_target.clone();
        if child_inode.file_type == ExtFileType::Symlink && symlink_target.is_none() {
            if let Ok(bytes) = read_inode_content(data, base_offset, sb, groups, &child_inode) {
                symlink_target = Some(String::from_utf8_lossy(&bytes).to_string());
            }
        }

        let entry = ExtEntry {
            ino: raw.ino,
            path: child_path.clone(),
            name: raw.name.clone(),
            parent_ino: dir_inode.ino,
            file_type: child_inode.file_type,
            mode: child_inode.mode,
            uid: child_inode.uid,
            gid: child_inode.gid,
            size: child_inode.size,
            symlink_target,
            mtime: child_inode.mtime,
        };

        out_entries.push(entry);

        if child_inode.file_type == ExtFileType::Directory {
            walk_directory_recursive(
                data,
                base_offset,
                sb,
                groups,
                &child_inode,
                &child_path,
                depth + 1,
                visited_inodes,
                out_entries,
            )?;
        }
    }

    Ok(())
}

/// Safely validates that a path destination stays strictly inside the target directory.
pub fn validate_safe_path(base_dir: &Path, rel_path: &str) -> Result<PathBuf> {
    let clean_rel = rel_path.trim_start_matches('/').trim_start_matches('\\');
    let mut resolved = PathBuf::from(base_dir);

    for part in clean_rel.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(CarverError::ExtFs(format!(
                "Path traversal attempt detected with '..' in path '{}'",
                rel_path
            )));
        }
        resolved.push(part);
    }

    Ok(resolved)
}

/// Safely extracts all files and directories in the archive to disk.
pub fn extract_archive_to_disk(
    data: &[u8],
    base_offset: usize,
    sb: &ExtSuperblock,
    groups: &[BlockGroupDescriptor],
    entries: &[ExtEntry],
    dest_dir: &Path,
) -> Result<usize> {
    fs::create_dir_all(dest_dir).map_err(|e| {
        CarverError::ExtractionFailed(format!(
            "Failed to create root destination directory '{}': {}",
            dest_dir.display(),
            e
        ))
    })?;

    let mut extracted_count = 0;

    for entry in entries {
        if entry.path == "/" {
            continue;
        }

        let target_path = validate_safe_path(dest_dir, &entry.path)?;

        match entry.file_type {
            ExtFileType::Directory => {
                fs::create_dir_all(&target_path).map_err(|e| {
                    CarverError::ExtractionFailed(format!(
                        "Failed to create directory '{}': {}",
                        target_path.display(),
                        e
                    ))
                })?;
                extracted_count += 1;
            }
            ExtFileType::RegularFile => {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        CarverError::ExtractionFailed(format!(
                            "Failed to create parent directory '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
                if let Ok(inode) = parse_inode(data, base_offset, sb, groups, entry.ino) {
                    let content = read_inode_content(data, base_offset, sb, groups, &inode)?;
                    fs::write(&target_path, &content).map_err(|e| {
                        CarverError::ExtractionFailed(format!(
                            "Failed to write file '{}': {}",
                            target_path.display(),
                            e
                        ))
                    })?;
                    extracted_count += 1;
                }
            }
            ExtFileType::Symlink => {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        CarverError::ExtractionFailed(format!(
                            "Failed to create parent dir for symlink '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
                if let Some(target) = &entry.symlink_target {
                    // Write placeholder text or symlink target descriptor for cross-platform portability
                    let symlink_content = format!("[SYMLINK -> {}]", target);
                    fs::write(&target_path, symlink_content.as_bytes()).map_err(|e| {
                        CarverError::ExtractionFailed(format!(
                            "Failed to write symlink target record '{}': {}",
                            target_path.display(),
                            e
                        ))
                    })?;
                    extracted_count += 1;
                }
            }
            _ => {}
        }
    }

    Ok(extracted_count)
}
