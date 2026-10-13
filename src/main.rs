// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::Parser;
use firm_carver::cli::Cli;
use firm_carver::error::Result;
use std::process;

mod commands;

fn run() -> Result<()> {
    let cli = Cli::parse();
    commands::dispatch(cli)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[Error] fcarver failed: {}", err);
        process::exit(1);
    }
}
