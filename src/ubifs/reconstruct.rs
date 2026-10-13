// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;
use crate::error::{CarverError, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub fn format_mode_string(mode: u32, file_type: UbifsFileType) -> String {
    let type_char = match file_type {
        UbifsFileType::Directory => 'd',
        UbifsFileType::Symlink => 'l',
        UbifsFileType::BlockDevice => 'b',
        UbifsFileType::CharDevice => 'c',
        UbifsFileType::Fifo => 'p',
        UbifsFileType::Socket => 's',
        _ => '-',
    };

    let rwx = |shift: u32| -> [char; 3] {
        let bits = (mode >> shift) & 0b111;
        [
            if (bits & 4) != 0 { 'r' } else { '-' },
            if (bits & 2) != 0 { 'w' } else { '-' },
            if (bits & 1) != 0 { 'x' } else { '-' },
        ]
    };

    let u = rwx(6);
    let g = rwx(3);
    let o = rwx(0);

    format!(
        "{}{}{}{}{}{}{}{}{}{}",
        type_char, u[0], u[1], u[2], g[0], g[1], g[2], o[0], o[1], o[2]
    )
}

pub fn reconstruct_filesystem(
    inodes: &HashMap<u64, UbifsInode>,
    dentries: &[UbifsDent],
) -> Vec<UbifsEntry> {
    let mut parent_to_children: HashMap<u64, Vec<&UbifsDent>> = HashMap::new();
    for d in dentries {
        parent_to_children.entry(d.parent_inum).or_default().push(d);
    }

    let mut entries = Vec::new();
    let mut visited = HashSet::new();

    // Include root directory if present
    if let Some(root_ino) = inodes.get(&UBIFS_ROOT_INO) {
        entries.push(UbifsEntry {
            inum: UBIFS_ROOT_INO,
            parent_inum: UBIFS_ROOT_INO,
            path: "/".to_string(),
            name: "/".to_string(),
            file_type: UbifsFileType::Directory,
            size: root_ino.size,
            mode: if root_ino.mode == 0 {
                0o755
            } else {
                root_ino.mode
            },
            uid: root_ino.uid,
            gid: root_ino.gid,
            mtime_sec: root_ino.mtime_sec,
            symlink_target: None,
        });
        visited.insert(UBIFS_ROOT_INO);
    }

    fn walk(
        cur_inum: u64,
        cur_path: &str,
        parent_to_children: &HashMap<u64, Vec<&UbifsDent>>,
        inodes: &HashMap<u64, UbifsInode>,
        visited: &mut HashSet<u64>,
        entries: &mut Vec<UbifsEntry>,
        depth: usize,
    ) {
        if depth > 32 {
            return;
        }

        if let Some(children) = parent_to_children.get(&cur_inum) {
            let mut sorted_children = children.clone();
            sorted_children.sort_by(|a, b| a.name.cmp(&b.name));

            for child in sorted_children {
                if child.name.is_empty() || child.name == "." || child.name == ".." {
                    continue;
                }

                let child_path = if cur_path == "/" {
                    format!("/{}", child.name)
                } else {
                    format!("{}/{}", cur_path, child.name)
                };

                let ino = inodes.get(&child.inum);
                let (size, mode, uid, gid, mtime_sec, symlink_target) = match ino {
                    Some(i) => (
                        i.size,
                        if i.mode == 0 {
                            if child.target_type == UbifsFileType::Directory {
                                0o755
                            } else {
                                0o644
                            }
                        } else {
                            i.mode
                        },
                        i.uid,
                        i.gid,
                        i.mtime_sec,
                        i.symlink_target.clone(),
                    ),
                    None => (
                        0,
                        if child.target_type == UbifsFileType::Directory {
                            0o755
                        } else {
                            0o644
                        },
                        0,
                        0,
                        0,
                        None,
                    ),
                };

                entries.push(UbifsEntry {
                    inum: child.inum,
                    parent_inum: child.parent_inum,
                    path: child_path.clone(),
                    name: child.name.clone(),
                    file_type: child.target_type,
                    size,
                    mode,
                    uid,
                    gid,
                    mtime_sec,
                    symlink_target,
                });
                visited.insert(child.inum);

                if child.target_type == UbifsFileType::Directory {
                    walk(
                        child.inum,
                        &child_path,
                        parent_to_children,
                        inodes,
                        visited,
                        entries,
                        depth + 1,
                    );
                }
            }
        }
    }

    walk(
        UBIFS_ROOT_INO,
        "/",
        &parent_to_children,
        inodes,
        &mut visited,
        &mut entries,
        0,
    );

    // If any dentries were outside the root hierarchy (e.g. unparented/fragmented LEBs), add them under /_lost_found/
    for d in dentries {
        if !visited.contains(&d.inum) && d.name != "." && d.name != ".." {
            let ino = inodes.get(&d.inum);
            let (size, mode, uid, gid, mtime_sec, symlink_target) = match ino {
                Some(i) => (
                    i.size,
                    i.mode,
                    i.uid,
                    i.gid,
                    i.mtime_sec,
                    i.symlink_target.clone(),
                ),
                None => (0, 0o644, 0, 0, 0, None),
            };
            entries.push(UbifsEntry {
                inum: d.inum,
                parent_inum: d.parent_inum,
                path: format!("/{}", d.name),
                name: d.name.clone(),
                file_type: d.target_type,
                size,
                mode,
                uid,
                gid,
                mtime_sec,
                symlink_target,
            });
            visited.insert(d.inum);
        }
    }

    entries
}

pub fn format_listing(entries: &[UbifsEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        let perm = format_mode_string(e.mode, e.file_type);
        let link_target = match &e.symlink_target {
            Some(t) => format!(" -> {}", t),
            None => String::new(),
        };
        out.push_str(&format!(
            "{:<10} {:4} {:4} {:8} {:6} {}{}\n",
            perm, e.uid, e.gid, e.size, e.inum, e.path, link_target
        ));
    }
    out
}

pub fn validate_safe_path(target_dir: &Path, rel_path: &str) -> Result<PathBuf> {
    let clean = rel_path.trim_start_matches('/');
    let candidate = target_dir.join(clean);

    for comp in Path::new(clean).components() {
        if matches!(
            comp,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(CarverError::ExtractionFailed(format!(
                "Path traversal attempt rejected: {}",
                rel_path
            )));
        }
    }

    Ok(candidate)
}

pub fn extract_archive_to_disk(
    entries: &[UbifsEntry],
    dest_dir: &Path,
    file_contents: &HashMap<u64, Vec<u8>>,
) -> Result<usize> {
    if !dest_dir.exists() {
        fs::create_dir_all(dest_dir).map_err(|e| {
            CarverError::ExtractionFailed(format!(
                "Failed to create extract destination {}: {}",
                dest_dir.display(),
                e
            ))
        })?;
    }

    let mut count = 0;
    for entry in entries {
        if entry.path == "/" {
            continue;
        }

        let target_path = validate_safe_path(dest_dir, &entry.path)?;

        match entry.file_type {
            UbifsFileType::Directory => {
                fs::create_dir_all(&target_path).map_err(|e| {
                    CarverError::ExtractionFailed(format!(
                        "Failed to create directory {}: {}",
                        target_path.display(),
                        e
                    ))
                })?;
                count += 1;
            }
            UbifsFileType::Regular => {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        CarverError::ExtractionFailed(format!(
                            "Failed to create parent dir {}: {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
                let content = file_contents.get(&entry.inum).cloned().unwrap_or_default();
                fs::write(&target_path, content).map_err(|e| {
                    CarverError::ExtractionFailed(format!(
                        "Failed to write file {}: {}",
                        target_path.display(),
                        e
                    ))
                })?;
                count += 1;
            }
            UbifsFileType::Symlink => {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        CarverError::ExtractionFailed(format!(
                            "Failed to create parent dir {}: {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
                if let Some(target) = &entry.symlink_target {
                    #[cfg(unix)]
                    {
                        let _ = std::os::unix::fs::symlink(target, &target_path);
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = fs::write(&target_path, format!("SYMLINK: {}", target));
                    }
                    count += 1;
                }
            }
            _ => {}
        }
    }

    Ok(count)
}
