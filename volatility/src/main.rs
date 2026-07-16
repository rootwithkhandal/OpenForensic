//! Standalone CLI for the Rust Volatility memory forensics engine.
//!
//! Usage:
//!   volatility -f <image_path> <profile>
//!   volatility --list-plugins

use clap::Parser;
use volatility::{run_analysis, list_supported_plugins};

/// OpenForensic Native Rust Volatility Engine — Memory forensics analysis tool.
#[derive(Parser, Debug)]
#[command(name = "volatility", version, about = "Native Rust memory forensics engine for OpenForensic")]
struct Args {
    /// Path to the memory dump file (.raw, .dmp, .vmem, .bin, .dd)
    #[arg(short = 'f', long = "file")]
    image_path: Option<String>,

    /// Analysis profile/plugin to run
    #[arg()]
    profile: Option<String>,

    /// List all supported analysis plugins
    #[arg(long = "list-plugins")]
    list_plugins: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.list_plugins {
        println!("\n  Supported Analysis Plugins:\n");
        for (name, desc) in list_supported_plugins() {
            println!("    {:<35} {}", name, desc);
        }
        println!();
        return;
    }

    let image_path = match args.image_path {
        Some(ref p) => p.as_str(),
        None => {
            eprintln!("Error: No memory image specified. Use -f <path>");
            std::process::exit(1);
        }
    };

    let profile = match args.profile {
        Some(ref p) => p.as_str(),
        None => {
            eprintln!("Error: No analysis profile specified.");
            eprintln!("Run with --list-plugins to see available plugins.");
            std::process::exit(1);
        }
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);

    // Spawn a task to print output lines as they arrive
    let print_task = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            println!("{}", line);
        }
    });

    match run_analysis(image_path, profile, tx).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("\nError: {}", e);
            std::process::exit(1);
        }
    }

    let _ = print_task.await;
}
