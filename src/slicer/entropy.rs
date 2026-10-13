// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

/// Point in a sliding-window entropy profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntropyWindow {
    /// Starting byte offset of this window
    pub offset: usize,
    /// Size of this window in bytes
    pub size: usize,
    /// Shannon entropy in bits per byte (0.0 to 8.0)
    pub entropy: f64,
}

/// Aggregated entropy profile across a data buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyProfile {
    /// Total buffer size analyzed
    pub total_size: usize,
    /// Window size in bytes
    pub window_size: usize,
    /// Step stride in bytes between consecutive windows
    pub step_size: usize,
    /// Overall average Shannon entropy across windows
    pub mean_entropy: f64,
    /// Minimum entropy observed in any window
    pub min_entropy: f64,
    /// Maximum entropy observed in any window
    pub max_entropy: f64,
    /// Window data points
    pub windows: Vec<EntropyWindow>,
}

/// Calculates Shannon entropy of a byte slice in bits per byte (0.0 ..= 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy.clamp(0.0, 8.0)
}

/// Calculates Chi-Square goodness-of-fit statistic against uniform byte distribution.
pub fn chi_squared_test(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let expected = data.len() as f64 / 256.0;
    let mut chi_sq = 0.0;
    for &c in &counts {
        let diff = c as f64 - expected;
        chi_sq += (diff * diff) / expected;
    }

    chi_sq
}

/// Computes a sliding-window Shannon entropy profile across a buffer.
pub fn compute_entropy_profile(
    data: &[u8],
    window_size: usize,
    step_size: usize,
) -> EntropyProfile {
    let window_size = window_size.max(16);
    let step_size = step_size.max(1);

    if data.is_empty() {
        return EntropyProfile {
            total_size: 0,
            window_size,
            step_size,
            mean_entropy: 0.0,
            min_entropy: 0.0,
            max_entropy: 0.0,
            windows: Vec::new(),
        };
    }

    let mut windows = Vec::new();
    let mut min_entropy = 8.0;
    let mut max_entropy = 0.0;
    let mut sum_entropy = 0.0;

    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + window_size).min(data.len());
        let window_slice = &data[offset..end];
        let ent = shannon_entropy(window_slice);

        if ent < min_entropy {
            min_entropy = ent;
        }
        if ent > max_entropy {
            max_entropy = ent;
        }
        sum_entropy += ent;

        windows.push(EntropyWindow {
            offset,
            size: end - offset,
            entropy: (ent * 10000.0).round() / 10000.0,
        });

        if offset + step_size >= data.len() || end == data.len() {
            break;
        }
        offset += step_size;
    }

    let mean_entropy = if !windows.is_empty() {
        ((sum_entropy / windows.len() as f64) * 10000.0).round() / 10000.0
    } else {
        0.0
    };

    if windows.is_empty() {
        min_entropy = 0.0;
        max_entropy = 0.0;
    }

    EntropyProfile {
        total_size: data.len(),
        window_size,
        step_size,
        mean_entropy,
        min_entropy: (min_entropy * 10000.0).round() / 10000.0,
        max_entropy: (max_entropy * 10000.0).round() / 10000.0,
        windows,
    }
}

/// Generates an ASCII terminal plot of the entropy curve.
pub fn render_ascii_entropy_plot(profile: &EntropyProfile, width: usize, height: usize) -> String {
    use std::fmt::Write;
    let mut out = String::new();

    if profile.windows.is_empty() {
        return "  [No entropy data to plot]\n".to_string();
    }

    let plot_w = width.clamp(20, 100);
    let plot_h = height.clamp(4, 20);

    let mut grid = vec![vec![' '; plot_w]; plot_h];
    let num_windows = profile.windows.len();

    for (i, w) in profile.windows.iter().enumerate() {
        let x = if num_windows > 1 {
            (i * (plot_w - 1)) / (num_windows - 1)
        } else {
            0
        };
        let normalized = (w.entropy / 8.0).clamp(0.0, 1.0);
        let y = ((normalized * (plot_h - 1) as f64).round() as usize).min(plot_h - 1);
        let grid_y = (plot_h - 1) - y;
        grid[grid_y][x] = '*';
    }

    let _ = writeln!(out, "  Entropy Curve (0.0 to 8.0 bits/byte):");
    for (row, grid_row) in grid.iter().enumerate().take(plot_h) {
        let level = 8.0 * (plot_h - 1 - row) as f64 / (plot_h - 1) as f64;
        let line: String = grid_row.iter().collect();
        let _ = writeln!(out, "  {:>4.1} |{}", level, line);
    }

    let axis = "-".repeat(plot_w);
    let _ = writeln!(out, "       +{}", axis);

    let max_off = profile.total_size.saturating_sub(1);
    let _ = writeln!(
        out,
        "       0x00000000{:>width$}",
        format!("0x{:08X}", max_off),
        width = plot_w.saturating_sub(10)
    );

    out
}
