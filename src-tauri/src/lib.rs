#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod acquisition;
pub mod hasher;
pub mod output;
pub mod report;
pub mod state;
pub mod error;
pub mod format;
pub mod platform;
pub mod memory;
pub mod locked_files;
pub mod consistency;
pub mod case_management;
pub mod yara_scanner;
pub mod pdf_report;
pub mod triage_db;
pub mod mobile_triage;
pub mod timeline;
pub mod ram_analysis;
pub mod plugins;
pub mod siem;
pub mod cli;
pub mod pgp;
pub mod encryption;

pub use state::{ActiveTaskState, clear_active_task, AcquisitionMode, AcquisitionModeState, require_analysis_mode};
