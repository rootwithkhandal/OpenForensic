use rusqlite::{Connection, Result};
use std::path::Path;

pub fn init_triage_db(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY,
            pid INTEGER,
            name TEXT,
            executable_path TEXT,
            command_line TEXT,
            memory_usage INTEGER
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS network_connections (
            id INTEGER PRIMARY KEY,
            protocol TEXT,
            local_address TEXT,
            foreign_address TEXT,
            state TEXT,
            pid INTEGER
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS browser_history (
            id INTEGER PRIMARY KEY,
            browser_name TEXT,
            url TEXT,
            title TEXT,
            visit_time TEXT,
            visit_count INTEGER
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS installed_browsers (
            id INTEGER PRIMARY KEY,
            browser_name TEXT,
            engine TEXT,
            user_name TEXT,
            profile_name TEXT,
            history_path TEXT,
            history_count INTEGER,
            status TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS browser_cookies (
            id INTEGER PRIMARY KEY,
            browser_name TEXT,
            host_key TEXT,
            name TEXT,
            value TEXT,
            path TEXT,
            creation_utc TEXT,
            expires_utc TEXT,
            is_secure INTEGER
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS browser_logins (
            id INTEGER PRIMARY KEY,
            browser_name TEXT,
            origin_url TEXT,
            username_value TEXT,
            password_value TEXT,
            creation_date TEXT,
            encryption_status TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS browser_downloads (
            id INTEGER PRIMARY KEY,
            browser_name TEXT,
            target_path TEXT,
            url TEXT,
            start_time TEXT,
            total_bytes INTEGER,
            state TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS browser_extensions (
            id INTEGER PRIMARY KEY,
            browser_name TEXT,
            extension_id TEXT,
            name TEXT,
            version TEXT,
            description TEXT,
            permissions TEXT,
            suspicious_flags TEXT,
            manifest_path TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY,
            log_name TEXT,
            event_id INTEGER,
            source TEXT,
            time_created TEXT,
            message TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS im_apps (
            id INTEGER PRIMARY KEY,
            app_name TEXT,
            app_type TEXT,
            user_name TEXT,
            install_path TEXT,
            data_path TEXT,
            artifacts_count INTEGER,
            status TEXT
        )",
        [],
    )?;


    conn.execute(
        "CREATE TABLE IF NOT EXISTS prefetch_executions (
            id INTEGER PRIMARY KEY,
            executable_name TEXT,
            file_path TEXT,
            run_count INTEGER,
            last_run_time TEXT,
            prefetch_hash TEXT,
            loaded_files TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS amcache_entries (
            id INTEGER PRIMARY KEY,
            source_type TEXT,
            file_path TEXT,
            sha1_hash TEXT,
            publisher TEXT,
            install_date TEXT,
            last_modified_time TEXT,
            execution_flag TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS srum_resource_usage (
            id INTEGER PRIMARY KEY,
            app_id TEXT,
            user_id TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            network_interface TEXT,
            timestamp TEXT,
            foreground_cycle_time INTEGER,
            background_cycle_time INTEGER
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS memory_triage (
            id INTEGER PRIMARY KEY,
            artifact_type TEXT,
            process_id INTEGER,
            details TEXT,
            risk_level TEXT,
            timestamp TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS network_triage (
            id INTEGER PRIMARY KEY,
            table_type TEXT,
            local_address TEXT,
            remote_address TEXT,
            state TEXT,
            extra_info TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS cloud_remote_triage (
            id INTEGER PRIMARY KEY,
            provider TEXT,
            account_user TEXT,
            config_path TEXT,
            status TEXT,
            last_accessed TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS iot_embedded_triage (
            id INTEGER PRIMARY KEY,
            device_or_image TEXT,
            component_type TEXT,
            config_key TEXT,
            config_value TEXT,
            notes TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS triage_audit_log (
            id INTEGER PRIMARY KEY,
            triage_category TEXT,
            execution_mode TEXT,
            purpose_scope TEXT,
            artifacts_collected TEXT,
            timestamp TEXT,
            prev_hash TEXT DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            entry_hash TEXT DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS pcap_capture_packets (
            id INTEGER PRIMARY KEY,
            packet_timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            info TEXT,
            correlated_pid INTEGER,
            correlated_process_name TEXT,
            risk_flags TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS dns_cache_entries (
            id INTEGER PRIMARY KEY,
            record_name TEXT,
            record_type TEXT,
            record_data TEXT,
            ttl INTEGER,
            source TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS arp_table_entries (
            id INTEGER PRIMARY KEY,
            ip_address TEXT,
            mac_address TEXT,
            interface_name TEXT,
            entry_type TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS wifi_profiles (
            id INTEGER PRIMARY KEY,
            ssid TEXT,
            authentication TEXT,
            encryption TEXT,
            password_or_key TEXT,
            last_connected TEXT,
            source TEXT
        )",
        [],
    )?;

    Ok(conn)
}
