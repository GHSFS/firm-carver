// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use crate::jffs2::decompress::decompress_payload;
use crate::jffs2::node::{RawDirent, RawInode};
use crate::jffs2::types::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const MAX_FILE_SIZE_LIMIT: usize = 64 * 1024 * 1024; // 64 MB guard against corrupt isize DOS

/// Formats POSIX file mode bits into a standard UNIX permissions string (e.g. `-rwxr-xr-x`).
pub fn format_mode_string(mode: u32, file_type: Jffs2FileType) -> String {
    let type_char = match file_type {
        Jffs2FileType::Directory => 'd',
        Jffs2FileType::Symlink => 'l',
        Jffs2FileType::BlockDevice => 'b',
        Jffs2FileType::CharDevice => 'c',
        Jffs2FileType::Fifo => 'p',
        Jffs2FileType::Socket => 's',
        _ => '-',
    };

    let rwx = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];

    let mut s = String::with_capacity(10);
    s.push(type_char);
    for (mask, c) in rwx {
        if (mode & mask) != 0 {
            s.push(c);
        } else {
            s.push('-');
        }
    }
    s
}

#[derive(Debug, Default)]
struct AssembledInode {
    mode: u32,
    uid: u16,
    gid: u16,
    mtime: u32,
    symlink_target: Option<String>,
    data: Vec<u8>,
}

/// Reconstructs filesystem entries from raw JFFS2 dirent and inode nodes.
pub fn reconstruct_filesystem(
    dirents: Vec<RawDirent>,
    inodes: Vec<RawInode>,
    cleanmarker_count: usize,
    endianness: Endianness,
    total_bytes: usize,
) -> Result<Jffs2Archive> {
    // 1. Group dirents by (pino, name) and select highest version (tombstone resolution)
    let mut latest_dirents: HashMap<(u32, String), RawDirent> = HashMap::new();
    for d in dirents {
        let key = (d.pino, d.name.clone());
        match latest_dirents.get(&key) {
            Some(existing) if existing.version >= d.version => {}
            _ => {
                latest_dirents.insert(key, d);
            }
        }
    }

    // Filter out unlinked / deleted files (ino == 0 is deletion tombstone)
    let active_dirents: Vec<RawDirent> = latest_dirents
        .into_values()
        .filter(|d| d.ino != 0)
        .collect();

    // 2. Group inode nodes by inode number (ino)
    let mut inode_map: HashMap<u32, Vec<RawInode>> = HashMap::new();
    for inode in inodes {
        inode_map.entry(inode.ino).or_default().push(inode);
    }

    // Sort inode chunks by version for each inode
    for chunk_list in inode_map.values_mut() {
        chunk_list.sort_by_key(|c| c.version);
    }

    // 3. Assemble file payload and metadata for each active inode
    let mut assembled_inodes: HashMap<u32, AssembledInode> = HashMap::new();

    for (&ino, chunk_list) in &inode_map {
        let latest_meta = chunk_list.last().unwrap();
        let mode = latest_meta.mode;
        let uid = latest_meta.uid;
        let gid = latest_meta.gid;
        let mtime = latest_meta.mtime;
        let isize = (latest_meta.isize as usize).min(MAX_FILE_SIZE_LIMIT);

        let is_symlink = (mode & 0o170000) == 0o120000;
        let mut file_buf = vec![0u8; isize];
        let mut symlink_target = None;

        for chunk in chunk_list {
            if chunk.csize == 0 && chunk.dsize == 0 {
                continue;
            }
            if let Ok(decompressed) =
                decompress_payload(&chunk.payload, chunk.compr, chunk.dsize as usize)
            {
                if is_symlink {
                    symlink_target = Some(String::from_utf8_lossy(&decompressed).to_string());
                } else {
                    let offset = chunk.offset as usize;
                    let end = (offset + decompressed.len()).min(MAX_FILE_SIZE_LIMIT);
                    if end > file_buf.len() {
                        file_buf.resize(end, 0);
                    }
                    if offset < file_buf.len() {
                        let copy_len = decompressed.len().min(file_buf.len() - offset);
                        file_buf[offset..offset + copy_len]
                            .copy_from_slice(&decompressed[..copy_len]);
                    }
                }
            }
        }

        assembled_inodes.insert(
            ino,
            AssembledInode {
                mode,
                uid,
                gid,
                mtime,
                symlink_target,
                data: file_buf,
            },
        );
    }

    // 4. Build directory hierarchy starting from root inode (ino 1)
    let mut children_map: HashMap<u32, Vec<RawDirent>> = HashMap::new();
    for d in active_dirents {
        children_map.entry(d.pino).or_default().push(d);
    }

    let mut entries = Vec::new();
    let mut visited_inos = HashSet::new();

    // Check if root inode (ino 1) exists in assembled inodes
    let (root_mode, root_uid, root_gid, root_mtime) = if let Some(info) = assembled_inodes.get(&1) {
        (info.mode, info.uid, info.gid, info.mtime)
    } else {
        (0o040755, 0, 0, 0)
    };

    entries.push(Jffs2Entry {
        ino: 1,
        pino: 0,
        name: "/".to_string(),
        path: "/".to_string(),
        file_type: Jffs2FileType::Directory,
        mode: root_mode,
        uid: root_uid,
        gid: root_gid,
        size: 0,
        mtime: root_mtime,
        symlink_target: None,
        data: Vec::new(),
    });
    visited_inos.insert(1);

    // Breadth-first traversal to construct paths
    let mut queue = vec![(1u32, "/".to_string())];
    while let Some((pino, parent_path)) = queue.pop() {
        if let Some(children) = children_map.remove(&pino) {
            for child in children {
                let path = if parent_path == "/" {
                    format!("/{}", child.name)
                } else {
                    format!("{}/{}", parent_path, child.name)
                };

                let info = if let Some(assembled) = assembled_inodes.remove(&child.ino) {
                    assembled
                } else {
                    let mode = if child.file_type == 4 {
                        0o040755
                    } else {
                        0o100644
                    };
                    AssembledInode {
                        mode,
                        uid: 0,
                        gid: 0,
                        mtime: child.mctime,
                        symlink_target: None,
                        data: Vec::new(),
                    }
                };

                let file_type = Jffs2FileType::from_raw(child.file_type, info.mode);
                let size = info.data.len() as u64;

                if file_type == Jffs2FileType::Directory && !visited_inos.contains(&child.ino) {
                    visited_inos.insert(child.ino);
                    queue.push((child.ino, path.clone()));
                }

                entries.push(Jffs2Entry {
                    ino: child.ino,
                    pino: child.pino,
                    name: child.name,
                    path,
                    file_type,
                    mode: info.mode,
                    uid: info.uid,
                    gid: info.gid,
                    size,
                    mtime: info.mtime,
                    symlink_target: info.symlink_target,
                    data: info.data,
                });
            }
        }
    }

    // Handle any orphaned dirents that weren't connected to root
    for (_pino, orphans) in children_map {
        for orphan in orphans {
            let path = format!("/lost+found/{}", orphan.name);
            let info = if let Some(assembled) = assembled_inodes.remove(&orphan.ino) {
                assembled
            } else {
                AssembledInode {
                    mode: 0o100644,
                    uid: 0,
                    gid: 0,
                    mtime: orphan.mctime,
                    symlink_target: None,
                    data: Vec::new(),
                }
            };
            let file_type = Jffs2FileType::from_raw(orphan.file_type, info.mode);
            entries.push(Jffs2Entry {
                ino: orphan.ino,
                pino: orphan.pino,
                name: orphan.name,
                path,
                file_type,
                mode: info.mode,
                uid: info.uid,
                gid: info.gid,
                size: info.data.len() as u64,
                mtime: info.mtime,
                symlink_target: info.symlink_target,
                data: info.data,
            });
        }
    }

    // Sort entries alphabetically by path
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let dirent_count = entries.len();
    let inode_count = inode_map.len();

    Ok(Jffs2Archive {
        endianness,
        cleanmarker_count,
        inode_node_count: inode_count,
        dirent_node_count: dirent_count,
        total_bytes_carved: total_bytes,
        entries,
    })
}

/// Safely resolves and extracts all entries into the target directory with path traversal defense.
pub fn extract_archive_to_disk(archive: &Jffs2Archive, out_dir: &Path) -> Result<usize> {
    if !out_dir.exists() {
        fs::create_dir_all(out_dir).map_err(|e| {
            CarverError::ExtractionFailed(format!(
                "Failed to create output dir {}: {}",
                out_dir.display(),
                e
            ))
        })?;
    }
    let canonical_root = out_dir.canonicalize().map_err(|e| {
        CarverError::ExtractionFailed(format!("Failed to canonicalize output dir: {}", e))
    })?;

    let mut extracted_count = 0;

    for entry in &archive.entries {
        if entry.path == "/" {
            continue;
        }

        // Sanitize path against directory traversal
        let mut clean_rel = PathBuf::new();
        for comp in Path::new(&entry.path).components() {
            match comp {
                Component::Normal(part) => clean_rel.push(part),
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    // Path traversal attempt: reject or skip to prevent escape
                    return Err(CarverError::ExtractionFailed(format!(
                        "Path traversal attempt detected in entry: {}",
                        entry.path
                    )));
                }
                Component::Prefix(_) => {}
            }
        }

        let target_path = canonical_root.join(&clean_rel);

        match entry.file_type {
            Jffs2FileType::Directory => {
                fs::create_dir_all(&target_path).map_err(|e| {
                    CarverError::ExtractionFailed(format!(
                        "Failed to create directory {}: {}",
                        target_path.display(),
                        e
                    ))
                })?;
                extracted_count += 1;
            }
            Jffs2FileType::Symlink => {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent).ok();
                }
                let target_desc = entry.symlink_target.as_deref().unwrap_or("unknown");
                // On Windows/cross-platform, write a symlink descriptor file to preserve target info
                let link_repr = format!("symlink: {}", target_desc);
                fs::write(&target_path, link_repr.as_bytes()).ok();
                extracted_count += 1;
            }
            _ => {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        CarverError::ExtractionFailed(format!(
                            "Failed to create parent directory for {}: {}",
                            target_path.display(),
                            e
                        ))
                    })?;
                }
                fs::write(&target_path, &entry.data).map_err(|e| {
                    CarverError::ExtractionFailed(format!(
                        "Failed to write file {}: {}",
                        target_path.display(),
                        e
                    ))
                })?;
                extracted_count += 1;
            }
        }
    }

    Ok(extracted_count)
}
