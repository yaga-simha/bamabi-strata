#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Binary entrypoint for `stratac` CLI.

use clap::Parser;
use stratac::{Cli, execute_cli};

fn main() {
    let cli = Cli::parse();
    let (code, output) = execute_cli(cli);
    if !output.is_empty() {
        println!("{output}");
    }
    std::process::exit(code);
}
