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

    Ok(conn)
}
