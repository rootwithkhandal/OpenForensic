use clap::{Parser, Subcommand};
use crate::hasher::HashAlgorithm;

#[derive(Parser, Debug)]
#[command(name = "openforensic", about = "Professional digital forensics suite (GUI & Headless CLI)", version)]
pub struct CliArgs {
    /// Run in headless CLI mode (bypassing Tauri GUI)
    #[arg(long, global = true)]
    pub cli: bool,

    /// Operation mode: capture (default) or analysis
    #[arg(long, global = true, default_value = "capture")]
    pub mode: String,

    #[command(subcommand)]
    pub command: Option<CliSubcommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CliSubcommand {
    /// List detected physical disks and block devices
    #[command(name = "list-devices", alias = "devices")]
    ListDevices,

    /// List logical OS volumes and mount points
    #[command(name = "list-volumes", alias = "volumes")]
    ListVolumes,

    /// Acquire a physical or logical disk image
    #[command(name = "acquire", alias = "image")]
    Acquire {
        /// Source device or file path (e.g., \\.\PhysicalDrive0 or /dev/sda)
        #[arg(short, long)]
        source: String,

        /// Destination directory or image file path
        #[arg(short, long)]
        dest: String,

        /// Output image format: raw, e01, aff
        #[arg(short, long, default_value = "raw")]
        format: String,

        /// Imaging mode: physical or logical
        #[arg(short, long, default_value = "physical")]
        mode: String,

        /// Compression algorithm: none, gzip, zstd
        #[arg(short, long, default_value = "none")]
        compression: String,

        /// Case number metadata
        #[arg(long, default_value = "CLI-001")]
        case_number: String,

        /// Examiner name metadata
        #[arg(long, default_value = "CLI-Investigator")]
        examiner: String,

        /// Evidence ID metadata
        #[arg(long, default_value = "EV-001")]
        evidence_id: String,

        /// Notes metadata
        #[arg(long, default_value = "Headless acquisition via OpenForensic CLI")]
        notes: String,

        /// Block size in KB (e.g., 512, 1024, 4096)
        #[arg(long, default_value_t = 1024)]
        block_size_kb: usize,

        /// Comma-separated list of hash algorithms (md5,sha1,sha256,sha512)
        #[arg(long, value_delimiter = ',', default_value = "md5,sha256")]
        hashes: Vec<String>,

        /// Comma-separated keywords for real-time regex searching
        #[arg(long, value_delimiter = ',')]
        keywords: Vec<String>,

        /// Path to custom YARA rules file (.yar) for real-time scanning
        #[arg(long)]
        yara_rules: Option<String>,

        /// Enable read verification after imaging
        #[arg(long, default_value_t = true)]
        verify: bool,
    },

    /// Perform rapid live system triage (processes, sockets, browser history, EVTX)
    #[command(name = "triage")]
    Triage {
        /// Output directory for triage database and extracted files
        #[arg(short, long)]
        dest: String,

        /// Skip volatile system state collection (processes, sockets, modules)
        #[arg(long)]
        no_volatile: bool,

        /// Skip registry hives and system configurations
        #[arg(long)]
        no_registry: bool,

        /// Skip browser activity history databases
        #[arg(long)]
        no_browsers: bool,

        /// Skip system event logs (EVTX / syslog)
        #[arg(long)]
        no_eventlogs: bool,

        /// Skip desktop messaging and communication apps triage (WhatsApp, Telegram, etc.)
        #[arg(long)]
        no_im_apps: bool,

        /// Enable real-time SIEM export to Splunk HEC or Wazuh socket (requires --mode analysis)
        #[arg(long)]
        siem_export: bool,

        /// SIEM endpoint URL / host:port / file path
        #[arg(long, default_value = "", required_if_eq("siem_export", "true"))]
        siem_endpoint: String,

        /// SIEM destination type: splunk_hec, wazuh_socket, wazuh_local_log
        #[arg(long, default_value = "splunk_hec")]
        siem_type: String,

        /// Auth token / API key for SIEM
        #[arg(long, default_value = "")]
        siem_token: String,

        /// SIEM index / sourcetype / tag
        #[arg(long, default_value = "openforensic_triage")]
        siem_index: String,
    },

    /// Perform live system VSS acquisition and RAM capture
    #[command(name = "live")]
    Live {
        /// System volume letter or mount point (e.g., C: or /)
        #[arg(short, long, default_value = "C:")]
        volume: String,

        /// Destination directory for live forensic artifacts
        #[arg(short, long)]
        dest: String,

        /// Capture physical memory (RAM dump)
        #[arg(long, default_value_t = true)]
        ram: bool,

        /// Copy OS-locked files (Registry hives, $MFT)
        #[arg(long, default_value_t = true)]
        locked_files: bool,

        /// Create physical VSS snapshot image
        #[arg(long)]
        image_vss: bool,

        /// Auto-cleanup VSS snapshot after acquisition
        #[arg(long, default_value_t = true)]
        cleanup: bool,

        /// Comma-separated hash algorithms
        #[arg(long, value_delimiter = ',', default_value = "md5,sha256")]
        hashes: Vec<String>,
    },

    /// Analyze RAM dump using Native Rust Volatility Engine & Threat Intelligence (requires --mode analysis)
    #[command(name = "ram", alias = "volatility")]
    Ram {
        /// Path to acquired RAM dump (.raw, .dmp, .vmem)
        #[arg(short, long)]
        dump: String,

        /// Volatility plugin profile: windows.pslist.PsList, windows.netstat.NetStat, windows.cmdline.CmdLine, windows.filescan.FileScan, windows.malfind.Malfind
        #[arg(short, long, default_value = "windows.pslist.PsList")]
        profile: String,

        /// Enable automated IOC reputation enrichment via AbuseIPDB and VirusTotal
        #[arg(long)]
        ioc_enrich: bool,
    },

    /// Generate a new PGP signing keypair for court-ready manifest provenance
    #[command(name = "pgp-keygen")]
    PgpKeygen {
        /// User ID string (e.g. "Forensic Investigator <exam@dfir.local>")
        #[arg(short, long, default_value = "OpenForensic Workstation <investigator@openforensic.local>")]
        user: String,
    },

    /// Create a detached ASCII-armored PGP signature (.asc) for an evidence file
    #[command(name = "pgp-sign")]
    PgpSign {
        /// Path to evidence or manifest file to sign
        #[arg(short, long)]
        file: String,
    },

    /// Verify a detached PGP signature (.asc) against an evidence file
    #[command(name = "pgp-verify")]
    PgpVerify {
        /// Path to evidence or manifest file
        #[arg(short, long)]
        file: String,

        /// Path to detached signature file (.asc). If not specified, defaults to <file>.asc
        #[arg(short, long)]
        sig: Option<String>,

        /// Optional path to public key file (.asc)
        #[arg(short, long)]
        pubkey: Option<String>,
    },
}

pub fn parse_hash_algorithms(names: &[String]) -> Vec<HashAlgorithm> {
    names.iter().filter_map(|s| {
        match s.trim().to_lowercase().as_str() {
            "md5" => Some(HashAlgorithm::MD5),
            "sha1" => Some(HashAlgorithm::SHA1),
            "sha256" => Some(HashAlgorithm::SHA256),
            "sha512" => Some(HashAlgorithm::SHA512),
            _ => None,
        }
    }).collect()
}
