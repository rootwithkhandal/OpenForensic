#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use clap::Parser;
    use super::super::args::{CliArgs, CliSubcommand, parse_hash_algorithms};
    use crate::hasher::HashAlgorithm;

    #[test]
    fn test_parse_list_devices() {
        let args = CliArgs::try_parse_from(["openforensic", "--cli", "list-devices"]).unwrap();
        assert!(args.cli);
        match args.command {
            Some(CliSubcommand::ListDevices) => {}
            _ => panic!("Expected ListDevices subcommand"),
        }
    }

    #[test]
    fn test_parse_acquire() {
        let args = CliArgs::try_parse_from([
            "openforensic",
            "--cli",
            "acquire",
            "--source", "/dev/sda",
            "--dest", "/mnt/evidence/img.raw",
            "--format", "e01",
            "--compression", "zstd",
            "--hashes", "md5,sha256,sha512",
            "--block-size-kb", "4096",
        ]).unwrap();

        assert!(args.cli);
        match args.command {
            Some(CliSubcommand::Acquire {
                source,
                dest,
                format,
                compression,
                block_size_kb,
                hashes,
                ..
            }) => {
                assert_eq!(source, "/dev/sda");
                assert_eq!(dest, "/mnt/evidence/img.raw");
                assert_eq!(format, "e01");
                assert_eq!(compression, "zstd");
                assert_eq!(block_size_kb, 4096);
                assert_eq!(hashes, vec!["md5", "sha256", "sha512"]);
            }
            _ => panic!("Expected Acquire subcommand"),
        }
    }

    #[test]
    fn test_parse_triage() {
        let args = CliArgs::try_parse_from([
            "openforensic",
            "--cli",
            "triage",
            "--dest", "/mnt/triage_out",
            "--no-browsers",
            "--siem-export",
            "--siem-type", "wazuh_socket",
            "--siem-endpoint", "10.0.0.5:1514",
        ]).unwrap();

        assert!(args.cli);
        match args.command {
            Some(CliSubcommand::Triage {
                dest,
                no_browsers,
                siem_export,
                siem_type,
                siem_endpoint,
                ..
            }) => {
                assert_eq!(dest, "/mnt/triage_out");
                assert!(no_browsers);
                assert!(siem_export);
                assert_eq!(siem_type, "wazuh_socket");
                assert_eq!(siem_endpoint, "10.0.0.5:1514");
            }
            _ => panic!("Expected Triage subcommand"),
        }
    }

    #[test]
    fn test_parse_hash_algorithms() {
        let names = vec!["md5".to_string(), "SHA256".to_string(), "invalid".to_string(), "sha512".to_string()];
        let algos = parse_hash_algorithms(&names);
        assert_eq!(algos.len(), 3);
        assert_eq!(algos[0], HashAlgorithm::MD5);
        assert_eq!(algos[1], HashAlgorithm::SHA256);
        assert_eq!(algos[2], HashAlgorithm::SHA512);
    }

    #[test]
    fn test_parse_triage_default_siem_endpoint() {
        let args = CliArgs::try_parse_from([
            "openforensic",
            "--cli",
            "triage",
            "--dest", "/mnt/triage_out",
        ]).unwrap();

        match args.command {
            Some(CliSubcommand::Triage {
                siem_endpoint,
                siem_export,
                ..
            }) => {
                assert!(!siem_export);
                assert_eq!(siem_endpoint, "");
            }
            _ => panic!("Expected Triage subcommand"),
        }
    }
}
