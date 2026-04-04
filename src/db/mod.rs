use anyhow::Result;
use rusqlite::{params, Connection};
use chrono::Utc;

pub struct ScanLog {
    pub id: i32,
    pub timestamp: String,
    pub module: String,
    pub target: String,
}

pub fn setup_db() -> Result<()> {
    let conn = Connection::open("secops.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            module TEXT NOT NULL,
            target TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

pub fn log_scan(module: &str, target: &str) -> Result<()> {
    let conn = Connection::open("secops.db")?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO scans (timestamp, module, target) VALUES (?1, ?2, ?3)",
        params![now, module, target],
    )?;
    Ok(())
}

pub fn get_history() -> Result<Vec<ScanLog>> {
    let conn = Connection::open("secops.db")?;
    let mut stmt = conn.prepare("SELECT id, timestamp, module, target FROM scans ORDER BY timestamp DESC")?;
    let rows = stmt.query_map([], |row| {
        Ok(ScanLog {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            module: row.get(2)?,
            target: row.get(3)?,
        })
    })?;

    let mut history = Vec::new();
    for row in rows {
        history.push(row?);
    }
    Ok(history)
}
