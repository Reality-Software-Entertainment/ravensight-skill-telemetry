//! Bounded, normalized retry storage. Never accepts raw hooks.
use crate::{Error, Event, Store};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryStats {
    pub queued: usize,
    pub dropped: u64,
    pub replayed: u64,
    pub expired: u64,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    events: Vec<Event>,
    stats: RetryStats,
}
/// Use a private, dedicated directory. A separate advisory lock protects atomic replacement.
/// Busy locks fail immediately; callers must surface that loss without blocking the host.
pub struct RetrySpool {
    root: PathBuf,
    capacity: usize,
    retention_ms: i64,
}
fn private_file(path: &Path) -> Result<fs::File, Error> {
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
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
impl RetrySpool {
    pub fn open(root: &Path, capacity: usize, retention_ms: i64) -> Result<Self, Error> {
        if capacity == 0 || capacity > 1024 || retention_ms <= 0 {
            return Err(Error::InvalidEvent);
        }
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(root) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::UnsafePath);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::UnsafePath);
            }
        }
        Ok(Self {
            root: root.into(),
            capacity,
            retention_ms,
        })
    }
    fn update<T>(&self, f: impl FnOnce(&mut Journal) -> Result<T, Error>) -> Result<T, Error> {
        self.update_inner(false, f)
    }
    fn update_inner<T>(
        &self,
        reset: bool,
        f: impl FnOnce(&mut Journal) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let lock = private_file(&self.root.join("lock"))?;
        lock.try_lock().map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "retry spool busy",
            ))
        })?;
        let path = self.root.join("queue.json");
        let mut file = private_file(&path)?;
        if !reset && file.metadata()?.len() > MAX_BYTES {
            return Err(Error::InvalidEvent);
        }
        let mut bytes = Vec::new();
        if !reset {
            Read::by_ref(&mut file)
                .take(MAX_BYTES + 1)
                .read_to_end(&mut bytes)?;
        }
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::InvalidEvent);
        }
        let mut journal: Journal = if bytes.is_empty() {
            Journal::default()
        } else {
            serde_json::from_slice(&bytes)?
        };
        if journal.events.len() > 1024 {
            return Err(Error::InvalidEvent);
        }
        for event in &journal.events {
            event.validate()?;
        }
        let result = f(&mut journal)?;
        journal.stats.queued = journal.events.len();
        let bytes = serde_json::to_vec(&journal)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::InvalidEvent);
        }
        let temporary = self.root.join("queue.next");
        let mut output = private_file(&temporary)?;
        output.set_len(0)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        fs::rename(temporary, path)?;
        #[cfg(unix)]
        fs::File::open(&self.root)?.sync_all()?;
        Ok(result)
    }
    /// Returns false for a duplicate or full queue; full-queue drops are counted.
    pub fn enqueue(&self, event: &Event) -> Result<bool, Error> {
        event.validate()?;
        self.update(|journal| {
            if journal.events.iter().any(|e| e.event_id == event.event_id) {
                return Ok(false);
            }
            if journal.events.len() >= self.capacity {
                journal.stats.dropped = journal.stats.dropped.saturating_add(1);
                return Ok(false);
            }
            journal.events.push(event.clone());
            Ok(true)
        })
    }
    /// Successful inserts and duplicate deliveries leave the queue. Failed writes remain queued.
    /// Crash after DB commit is safe: Store deduplicates the next replay by event ID.
    pub fn replay(&self, store: &mut Store, now_ms: i64) -> Result<RetryStats, Error> {
        self.update(|journal| {
            let mut unavailable = false;
            journal.events.retain(|event| {
                if event.received_ms < now_ms.saturating_sub(self.retention_ms) {
                    journal.stats.expired = journal.stats.expired.saturating_add(1);
                    return false;
                }
                if unavailable {
                    return true;
                }
                if store.append(event, now_ms).is_ok() {
                    journal.stats.replayed = journal.stats.replayed.saturating_add(1);
                    false
                } else {
                    unavailable = true;
                    true
                }
            });
            journal.stats.queued = journal.events.len();
            Ok(journal.stats.clone())
        })
    }
    pub fn stats(&self) -> Result<RetryStats, Error> {
        self.update(|j| {
            let mut s = j.stats.clone();
            s.queued = j.events.len();
            Ok(s)
        })
    }
    pub fn purge(&self) -> Result<(), Error> {
        self.update_inner(true, |_| Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::event;
    #[test]
    fn purge_recovers_corrupt_or_oversized_queue_without_parsing_it() {
        let t = tempfile::tempdir().unwrap();
        let spool = RetrySpool::open(&t.path().join("retry"), 1, 100).unwrap();
        spool.enqueue(&event(1)).unwrap();
        let path = spool.root.join("queue.json");
        fs::write(&path, b"broken json SECRET").unwrap();
        assert!(spool.stats().is_err());
        spool.purge().unwrap();
        assert_eq!(spool.stats().unwrap().queued, 0);
        private_file(&path).unwrap().set_len(MAX_BYTES + 1).unwrap();
        assert!(spool.stats().is_err());
        spool.purge().unwrap();
        assert!(spool.enqueue(&event(2)).unwrap());
    }
    #[test]
    fn bounded_deduplicated_replay_survives_reopening() {
        let t = tempfile::tempdir().unwrap();
        let spool = RetrySpool::open(&t.path().join("retry"), 1, 100).unwrap();
        assert!(spool.enqueue(&event(1)).unwrap());
        assert!(!spool.enqueue(&event(1)).unwrap());
        assert!(!spool.enqueue(&event(2)).unwrap());
        assert_eq!(spool.stats().unwrap().dropped, 1);
        let mut store = Store::open(&t.path().join("db"), 10, 100).unwrap();
        store.append(&event(1), 1).unwrap(); // simulate crash after insertion
        let spool = RetrySpool::open(&t.path().join("retry"), 1, 100).unwrap();
        assert_eq!(spool.replay(&mut store, 2).unwrap().queued, 0);
        assert_eq!(store.events(2).unwrap().len(), 1);
    }
    #[test]
    fn locked_db_keeps_events_then_replays_and_expires() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("db");
        let mut store = Store::open(&path, 10, 100).unwrap();
        let spool = RetrySpool::open(&t.path().join("retry"), 10, 100).unwrap();
        spool.enqueue(&event(1)).unwrap();
        let lock = rusqlite::Connection::open(&path).unwrap();
        lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
        assert_eq!(spool.replay(&mut store, 2).unwrap().queued, 1);
        lock.execute_batch("ROLLBACK").unwrap();
        assert_eq!(spool.replay(&mut store, 2).unwrap().queued, 0);
        spool.enqueue(&event(3)).unwrap();
        assert_eq!(spool.replay(&mut store, 200).unwrap().expired, 1);
    }
    #[test]
    fn rejects_unprojected_events_and_busy_lock() {
        let t = tempfile::tempdir().unwrap();
        let spool = RetrySpool::open(&t.path().join("retry"), 1, 100).unwrap();
        let mut invalid = event(1);
        invalid.skill = Some("secret prompt".into());
        assert!(spool.enqueue(&invalid).is_err());
        let lock = private_file(&spool.root.join("lock")).unwrap();
        lock.lock().unwrap();
        assert!(spool.enqueue(&event(1)).is_err());
    }
}
