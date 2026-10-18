//! Local-only, content-free skill activity. Producer reports are not attestations.
mod retry;
pub use retry::{RetrySpool, RetryStats};

use hmac::{Hmac, Mac};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fs, io::Write, path::Path, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid event")]
    InvalidEvent,
    #[error("unsupported schema version")]
    UnsupportedVersion,
    #[error("unsafe local storage path")]
    UnsafePath,
    #[error("local storage error")]
    Io(#[from] std::io::Error),
    #[error("database error")]
    Sql(#[from] rusqlite::Error),
    #[error("event encoding error")]
    Json(#[from] serde_json::Error),
}

/// ASCII metadata identifiers only. This is validation, not a secret detector.
/// Callers must never put arbitrary prompt or command content into these fields.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
}
fn valid_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

#[derive(Clone)]
pub struct Identity([u8; 32]);
impl Identity {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    /// Domain-separated HMAC; no raw session IDs, paths or invocation IDs leave the adapter.
    pub fn id(&self, domain: &str, values: &[&str]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("fixed key size");
        for value in std::iter::once(domain).chain(values.iter().copied()) {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value.as_bytes());
        }
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    Observed,
    Reported,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Started,
    Checking,
    Finished,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Failed,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Activity {
    Invoked,
    InstructionsLoaded,
    InvocationFailed,
    StageReported {
        stage: Stage,
    },
    OutcomeReported {
        outcome: Outcome,
        checks_passed: u32,
        checks_failed: u32,
    },
    SessionStarted,
    SessionEnded,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: String,
    pub project_id: String,
    pub session_id: String,
    pub invocation_id: Option<String>,
    pub skill: Option<String>,
    pub source_version: String,
    /// Receipt timestamp. Do not pretend hooks provide a precise execution timestamp.
    pub received_ms: i64,
    pub evidence: Evidence,
    pub activity: Activity,
}
impl Event {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 {
            return Err(Error::UnsupportedVersion);
        }
        let is_session = matches!(
            self.activity,
            Activity::SessionStarted | Activity::SessionEnded
        );
        let report = matches!(
            self.activity,
            Activity::StageReported { .. } | Activity::OutcomeReported { .. }
        );
        if !valid_id(&self.event_id)
            || !valid_id(&self.project_id)
            || !valid_id(&self.session_id)
            || self.received_ms < 0
            || !valid_name(&self.source_version)
            || self.invocation_id.as_ref().is_some_and(|id| !valid_id(id))
            || self.skill.as_ref().is_some_and(|s| !valid_name(s))
            || (is_session && (self.skill.is_some() || self.invocation_id.is_some()))
            || (!is_session && (self.skill.is_none() || self.invocation_id.is_none()))
            || (report != (self.evidence == Evidence::Reported))
        {
            return Err(Error::InvalidEvent);
        }
        Ok(())
    }
    pub fn summary(&self) -> String {
        let skill = self.skill.as_deref().unwrap_or("Session");
        let action = match &self.activity {
            Activity::Invoked => "invoked (observed)".into(),
            Activity::InstructionsLoaded => {
                "instructions loaded; outcome unknown (observed)".into()
            }
            Activity::InvocationFailed => "invocation failed (observed)".into(),
            Activity::StageReported { stage } => format!("stage {stage:?} (reported)"),
            Activity::OutcomeReported {
                outcome,
                checks_passed,
                checks_failed,
            } => format!(
                "outcome {outcome:?}: {checks_passed} checks passed, {checks_failed} failed (reported)"
            ),
            Activity::SessionStarted => {
                "started or resumed; prior outcomes unchanged (observed)".into()
            }
            Activity::SessionEnded => "ended; unreported outcomes remain unknown (observed)".into(),
        };
        format!("{skill}: {action}")
    }
}

/// Bounded event journal. Export explicitly with `export_jsonl`; no network code exists.
/// Duplicate IDs are ignored. Rows expire by receipt time. Evictions are counted.
pub struct Store {
    db: Connection,
    max_events: usize,
    retention_ms: i64,
}
impl Store {
    pub fn open(path: &Path, max_events: usize, retention_ms: i64) -> Result<Self, Error> {
        if max_events == 0 || max_events > 1_000_000 || retention_ms <= 0 {
            return Err(Error::InvalidEvent);
        }
        if let Ok(meta) = fs::symlink_metadata(path) {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(Error::UnsafePath);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(Error::UnsafePath);
                }
            }
        } else {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(path)?;
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_millis(50))?;
        // Keep the database itself bounded too; no unbounded WAL sidecar.
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON; PRAGMA max_page_count=32768;
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, received_ms INTEGER NOT NULL, terminal INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_time ON events(received_ms);
            CREATE TABLE IF NOT EXISTS stats(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            INSERT OR IGNORE INTO stats VALUES('evicted',0);")?;
        Ok(Self {
            db,
            max_events,
            retention_ms,
        })
    }
    pub fn append(&mut self, event: &Event, now_ms: i64) -> Result<bool, Error> {
        event.validate()?;
        let terminal = matches!(
            event.activity,
            Activity::OutcomeReported { .. } | Activity::SessionEnded | Activity::InvocationFailed
        );
        let tx = self.db.transaction()?;
        tx.execute(
            "DELETE FROM events WHERE received_ms < ?1",
            [now_ms.saturating_sub(self.retention_ms)],
        )?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO events VALUES(?1,?2,?3,?4)",
            params![
                event.event_id,
                event.received_ms,
                terminal,
                serde_json::to_string(event)?
            ],
        )?;
        let count: usize = tx.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        if count > self.max_events {
            let extra = count - self.max_events;
            tx.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY terminal ASC, received_ms ASC, rowid ASC LIMIT ?1)", [extra])?;
            tx.execute(
                "UPDATE stats SET value=value+?1 WHERE name='evicted'",
                [extra],
            )?;
        }
        tx.commit()?;
        Ok(n != 0)
    }
    pub fn events(&self, now_ms: i64) -> Result<Vec<Event>, Error> {
        self.db.execute(
            "DELETE FROM events WHERE received_ms < ?1",
            [now_ms.saturating_sub(self.retention_ms)],
        )?;
        let mut stmt = self.db.prepare(
            "SELECT body FROM events WHERE received_ms >= ?1 ORDER BY received_ms,rowid",
        )?;
        let bodies = stmt.query_map([now_ms.saturating_sub(self.retention_ms)], |r| {
            r.get::<_, String>(0)
        })?;
        bodies
            .map(|b| {
                let e: Event = serde_json::from_str(&b?)?;
                e.validate()?;
                Ok(e)
            })
            .collect()
    }
    pub fn evicted(&self) -> Result<u64, Error> {
        Ok(self
            .db
            .query_row("SELECT value FROM stats WHERE name='evicted'", [], |r| {
                r.get(0)
            })?)
    }
    pub fn purge(&mut self) -> Result<(), Error> {
        self.db
            .execute_batch("DELETE FROM events; UPDATE stats SET value=0; VACUUM;")?;
        Ok(())
    }
    /// OTLP JSON log envelope for an explicit file/stdout export. No collector or network access.
    pub fn export_otlp_json(&self, now_ms: i64, writer: impl Write) -> Result<(), Error> {
        let records: Vec<_> = self.events(now_ms)?.iter().map(|event| {
            serde_json::json!({
                "timeUnixNano": ((event.received_ms as u128) * 1_000_000).to_string(),
                "severityNumber": 9, "severityText": "INFO",
                "body": {"stringValue": event.summary()},
                "attributes": [
                    {"key":"event.id", "value":{"stringValue":event.event_id}},
                    {"key":"project.id", "value":{"stringValue":event.project_id}},
                    {"key":"session.id", "value":{"stringValue":event.session_id}},
                    {"key":"event.json", "value":{"stringValue":serde_json::to_string(event).expect("typed event serialization")}}
                ]
            })
        }).collect();
        serde_json::to_writer(
            writer,
            &serde_json::json!({"resourceLogs":[{
                "resource":{"attributes":[]}, "scopeLogs":[{
                    "scope":{"name":"skill-telemetry", "version":env!("CARGO_PKG_VERSION")},
                    "logRecords":records
                }]
            }]}),
        )?;
        Ok(())
    }
    pub fn export_jsonl(&self, now_ms: i64, mut writer: impl Write) -> Result<(), Error> {
        for event in self.events(now_ms)? {
            serde_json::to_writer(&mut writer, &event)?;
            writer.write_all(b"\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn event(n: i64) -> Event {
        let i = Identity::new([7; 32]);
        Event {
            schema_version: 1,
            event_id: i.id("event", &[&n.to_string()]),
            project_id: i.id("project", &["/private/game"]),
            session_id: i.id("session", &["s"]),
            invocation_id: Some(i.id("invocation", &["t"])),
            skill: Some("demo".into()),
            source_version: "fixture".into(),
            received_ms: n,
            evidence: Evidence::Observed,
            activity: Activity::Invoked,
        }
    }
    #[test]
    fn identities_are_domain_separated_and_keyed() {
        let a = Identity::new([1; 32]);
        let b = Identity::new([2; 32]);
        assert_ne!(a.id("session", &["x"]), a.id("project", &["x"]));
        assert_ne!(a.id("session", &["x"]), b.id("session", &["x"]));
        assert_ne!(a.id("s", &["a", "bc"]), a.id("s", &["ab", "c"]));
    }
    #[test]
    fn unknown_fields_rejected() {
        let mut e = serde_json::to_value(event(1)).unwrap();
        e["prompt"] = serde_json::json!("secret");
        assert!(serde_json::from_value::<Event>(e).is_err());
    }
    #[test]
    fn evidence_and_schema_validated() {
        let mut e = event(1);
        e.evidence = Evidence::Reported;
        assert!(e.validate().is_err());
        e = event(1);
        e.schema_version = 2;
        assert!(matches!(e.validate(), Err(Error::UnsupportedVersion)));
    }
    #[test]
    fn load_is_not_completion() {
        let mut e = event(1);
        e.activity = Activity::InstructionsLoaded;
        assert!(e.summary().contains("outcome unknown"));
    }
    #[test]
    fn durable_deduplicated_bounded_journal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events.db");
        {
            let mut s = Store::open(&path, 2, 100).unwrap();
            assert!(s.append(&event(1), 1).unwrap());
            assert!(!s.append(&event(1), 1).unwrap());
            s.append(&event(2), 2).unwrap();
            s.append(&event(3), 3).unwrap();
            assert_eq!(s.events(3).unwrap().len(), 2);
            assert_eq!(s.evicted().unwrap(), 1);
        }
        let s = Store::open(&path, 2, 100).unwrap();
        assert_eq!(s.events(3).unwrap().len(), 2);
        assert_eq!(s.events(200).unwrap().len(), 0);
    }
    #[test]
    fn reading_physically_prunes_expired_rows() {
        let t = tempfile::tempdir().unwrap();
        let mut s = Store::open(&t.path().join("db"), 10, 10).unwrap();
        s.append(&event(1), 1).unwrap();
        assert!(s.events(20).unwrap().is_empty());
        let n: i64 =
            s.db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                .unwrap();
        assert_eq!(n, 0);
    }
    #[test]
    fn preserves_outcomes_before_progress() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = Store::open(&tmp.path().join("db"), 1, 100).unwrap();
        let mut e = event(1);
        e.activity = Activity::OutcomeReported {
            outcome: Outcome::Passed,
            checks_passed: 1,
            checks_failed: 0,
        };
        e.evidence = Evidence::Reported;
        s.append(&e, 1).unwrap();
        s.append(&event(2), 2).unwrap();
        assert_eq!(s.events(2).unwrap(), vec![e]);
        s.purge().unwrap();
        assert!(s.events(2).unwrap().is_empty());
    }
    #[test]
    fn exported_events_never_include_raw_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = Store::open(&tmp.path().join("db"), 10, 100).unwrap();
        s.append(&event(1), 1).unwrap();
        let mut out = vec![];
        s.export_jsonl(1, &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("/private/game"));
    }
    #[test]
    fn otlp_has_precise_receipt_time_and_only_projected_metadata() {
        let t = tempfile::tempdir().unwrap();
        let mut store = Store::open(&t.path().join("db"), 10, 100).unwrap();
        store.append(&event(12), 12).unwrap();
        let mut out = Vec::new();
        store.export_otlp_json(12, &mut out).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let records = &value["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
        assert_eq!(records[0]["timeUnixNano"], "12000000");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("/private/game"));
        assert!(!text.contains("traceId")); // no invented cross-system trace correlation
    }
    #[cfg(unix)]
    #[test]
    fn refuses_symlink_storage() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        symlink(t.path().join("target"), t.path().join("link")).unwrap();
        assert!(matches!(
            Store::open(&t.path().join("link"), 2, 100),
            Err(Error::UnsafePath)
        ));
    }
}
