//! Dual-tier local relational storage for Open Humanity.
//!
//! Enforces SQLite WAL mode, foreign keys, 7-day TTL sweeps,
//! and Cortex memory promotion for verified resolutions.

use beacon_core::schema::{BeaconTopic, DistressNanobeacon};
use rusqlite::{params, Connection, Result};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const DEFAULT_TTL_SECONDS: u64 = 7 * 86400; // 7 days

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone)]
pub struct SolvedEntry {
    pub fingerprint_hash: [u8; 32],
    pub topic: BeaconTopic,
    pub solution_patch: String,
    pub verified_at: u64,
    pub promoted_to_cortex: bool,
}

pub struct BeaconStorage {
    conn: Connection,
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl BeaconStorage {
    pub fn open_default() -> std::result::Result<Self, StorageError> {
        let mut path = dirs_fallback_local_data();
        std::fs::create_dir_all(&path)?;
        path.push("beacon.sqlite");
        Self::open(&path)
    }

    pub fn open_in_memory() -> std::result::Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn,
            db_path: PathBuf::from(":memory:"),
        };
        storage.init_tables()?;
        Ok(storage)
    }

    pub fn open<P: AsRef<Path>>(path: P) -> std::result::Result<Self, StorageError> {
        let db_path = path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&db_path)?;
        let storage = Self { conn, db_path };
        storage.init_tables()?;
        Ok(storage)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.pragma_update(None, "journal_mode", "WAL")?;
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        self.conn.pragma_update(None, "busy_timeout", 5000)?;

        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS beacons_out (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                topic INTEGER NOT NULL,
                sender_pubkey BLOB NOT NULL,
                fingerprint_hash BLOB NOT NULL,
                compiler_code INTEGER,
                arch TEXT NOT NULL,
                title TEXT NOT NULL,
                compact_summary TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS beacons_in (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                topic INTEGER NOT NULL,
                sender_pubkey BLOB NOT NULL,
                fingerprint_hash BLOB NOT NULL,
                title TEXT NOT NULL,
                compact_summary TEXT NOT NULL,
                received_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS solved_cache (
                fingerprint_hash BLOB PRIMARY KEY,
                topic INTEGER NOT NULL,
                solution_patch TEXT NOT NULL,
                verified_at INTEGER NOT NULL,
                promoted_to_cortex INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS peer_reputation (
                pubkey BLOB PRIMARY KEY,
                successful_resolutions INTEGER NOT NULL DEFAULT 0,
                failed_resolutions INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    pub fn record_outbound_beacon(&self, beacon: &DistressNanobeacon) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.conn.execute(
            "INSERT OR REPLACE INTO beacons_out (
                id, timestamp, topic, sender_pubkey, fingerprint_hash,
                compiler_code, arch, title, compact_summary, status, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                beacon.beacon_id.to_string(),
                beacon.timestamp,
                beacon.topic as u8,
                &beacon.sender_pubkey[..],
                &beacon.fingerprint.hash[..],
                beacon.fingerprint.compiler_code,
                beacon.fingerprint.hardware_arch,
                beacon.title,
                beacon.compact_summary,
                "pending",
                now,
            ],
        )?;
        Ok(())
    }

    pub fn record_inbound_beacon(&self, beacon: &DistressNanobeacon) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.conn.execute(
            "INSERT OR REPLACE INTO beacons_in (
                id, timestamp, topic, sender_pubkey, fingerprint_hash,
                title, compact_summary, received_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                beacon.beacon_id.to_string(),
                beacon.timestamp,
                beacon.topic as u8,
                &beacon.sender_pubkey[..],
                &beacon.fingerprint.hash[..],
                beacon.title,
                beacon.compact_summary,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn insert_solved_entry(
        &self,
        fingerprint_hash: &[u8; 32],
        topic: BeaconTopic,
        patch: &str,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.conn.execute(
            "INSERT OR REPLACE INTO solved_cache (
                fingerprint_hash, topic, solution_patch, verified_at, promoted_to_cortex
            ) VALUES (?1, ?2, ?3, ?4, 0)",
            params![
                &fingerprint_hash[..],
                topic as u8,
                patch,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn get_solved_entry(&self, fingerprint_hash: &[u8; 32]) -> Result<Option<SolvedEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint_hash, topic, solution_patch, verified_at, promoted_to_cortex
             FROM solved_cache WHERE fingerprint_hash = ?1",
        )?;

        let mut rows = stmt.query(params![&fingerprint_hash[..]])?;
        if let Some(row) = rows.next()? {
            let hash_blob: Vec<u8> = row.get(0)?;
            let mut hash = [0u8; 32];
            if hash_blob.len() == 32 {
                hash.copy_from_slice(&hash_blob);
            }
            let topic_raw: u8 = row.get(1)?;
            let topic = match topic_raw {
                0 => BeaconTopic::RustCompilation,
                1 => BeaconTopic::MojoSimd,
                2 => BeaconTopic::ModularMaxServing,
                3 => BeaconTopic::HardwareTopology,
                4 => BeaconTopic::SecurityAudit,
                5 => BeaconTopic::ProtocolCoordination,
                _ => BeaconTopic::AgentRecursion,
            };
            let patch: String = row.get(2)?;
            let verified_at: u64 = row.get(3)?;
            let promoted: i64 = row.get(4)?;

            Ok(Some(SolvedEntry {
                fingerprint_hash: hash,
                topic,
                solution_patch: patch,
                verified_at,
                promoted_to_cortex: promoted != 0,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn sweep_expired(&self, ttl_seconds: u64) -> Result<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(ttl_seconds);

        let count_out = self.conn.execute(
            "DELETE FROM beacons_out WHERE created_at <= ?1",
            params![cutoff],
        )?;

        let count_in = self.conn.execute(
            "DELETE FROM beacons_in WHERE received_at <= ?1",
            params![cutoff],
        )?;

        Ok(count_out + count_in)
    }

    pub fn mark_promoted_to_cortex(&self, fingerprint_hash: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "UPDATE solved_cache SET promoted_to_cortex = 1 WHERE fingerprint_hash = ?1",
            params![&fingerprint_hash[..]],
        )?;
        Ok(())
    }

    pub fn transaction(&mut self) -> std::result::Result<rusqlite::Transaction<'_>, StorageError> {
        Ok(self.conn.transaction()?)
    }

    pub fn count_outbound(&self) -> std::result::Result<usize, StorageError> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM beacons_out")?;
        let count: usize = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    pub fn count_inbound(&self) -> std::result::Result<usize, StorageError> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM beacons_in")?;
        let count: usize = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    pub fn record_outbound_beacon_tx(
        tx: &rusqlite::Transaction<'_>,
        packet: &DistressNanobeacon,
    ) -> std::result::Result<(), StorageError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        tx.execute(
            "INSERT OR REPLACE INTO beacons_out (
                id, timestamp, topic, sender_pubkey, fingerprint_hash,
                compiler_code, arch, title, compact_summary, status, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                packet.beacon_id.to_string(),
                packet.timestamp,
                packet.topic as u8,
                &packet.sender_pubkey[..],
                &packet.fingerprint.hash[..],
                packet.fingerprint.compiler_code,
                packet.fingerprint.hardware_arch,
                packet.title,
                packet.compact_summary,
                "pending",
                now,
            ],
        )?;
        Ok(())
    }
}

fn dirs_fallback_local_data() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/open-humanity")
    } else {
        PathBuf::from("./.open-humanity-data")
    }
}
