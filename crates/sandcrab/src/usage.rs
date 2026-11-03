//! Descriptor-relative, bounded observations of allocated storage. A scan is not
//! a quota: concurrent writes and open unlinked files can escape an observation.
use rustix::fs::{CWD, Dir, Mode, OFlags, ResolveFlags, openat2};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub bytes: u64,
    pub inodes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    Complete(Usage),
    Exceeded(Usage),
    Unavailable,
}

#[derive(Clone)]
struct Sample {
    observation: Observation,
    at_millis: u64,
    next: Instant,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn allow_growth(sample: &Option<Sample>) -> Result<(), &'static str> {
    match sample.as_ref().map(|s| &s.observation) {
        Some(Observation::Complete(_)) => Ok(()),
        Some(Observation::Exceeded(_)) => Err("STORAGE_LIMIT"),
        Some(Observation::Unavailable) | None => Err("STORAGE_USAGE_UNAVAILABLE"),
    }
}

fn value(limit: Usage, sample: &Option<Sample>) -> Value {
    let (state, usage) = match sample.as_ref().map(|s| &s.observation) {
        Some(Observation::Complete(usage)) => ("complete", Some(usage)),
        Some(Observation::Exceeded(usage)) => ("exceeded", Some(usage)),
        Some(Observation::Unavailable) => ("unavailable", None),
        None => ("pending", None),
    };
    json!({"mode":"periodic","state":state,"observedAtMillis":sample.as_ref().map(|s|s.at_millis),
        "allocatedBytes":usage.map(|u|u.bytes),"inodes":usage.map(|u|u.inodes),
        "byteLimit":limit.bytes,"inodeLimit":(limit.inodes != u64::MAX).then_some(limit.inodes)})
}

/// A derived observation, never durable volume authority. Scanning does not hold
/// the sample lock used by requests; incomplete observations deny new growth.
pub struct Account {
    path: PathBuf,
    limit: Usage,
    sample: Mutex<Option<Sample>>,
    scanning: Mutex<()>,
}
impl Account {
    pub fn new(path: PathBuf, limit: Usage) -> Self {
        Self {
            path,
            limit,
            sample: Mutex::new(None),
            scanning: Mutex::new(()),
        }
    }

    pub fn pending(&self) -> bool {
        self.sample.lock().unwrap().is_none()
    }

    pub fn refresh(&self, force: bool, stopped: &AtomicBool) {
        let _scan = if force {
            self.scanning.lock().unwrap()
        } else {
            let Ok(scan) = self.scanning.try_lock() else {
                return;
            };
            scan
        };
        if !force
            && self
                .sample
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|s| Instant::now() < s.next)
        {
            return;
        }
        let observation = measure(&self.path, self.limit, stopped);
        *self.sample.lock().unwrap() = Some(Sample {
            observation,
            at_millis: now_millis(),
            next: Instant::now() + Duration::from_secs(1),
        });
    }

    pub fn allow_growth(&self) -> Result<(), &'static str> {
        allow_growth(&self.sample.lock().unwrap())
    }

    pub fn value(&self) -> Value {
        value(self.limit, &self.sample.lock().unwrap())
    }
}

/// The store supplies its current owned inventory while holding the inventory lock.
/// This summary combines complete scans; it never walks a second aggregate tree.
pub struct Pool {
    limit: Usage,
    sample: Mutex<Option<Sample>>,
}
impl Pool {
    pub fn new(bytes: u64) -> Self {
        Self {
            limit: Usage {
                bytes,
                inodes: u64::MAX,
            },
            sample: Mutex::new(None),
        }
    }

    pub fn refresh<'a>(
        &self,
        overhead: io::Result<Usage>,
        accounts: impl Iterator<Item = &'a Account>,
    ) {
        let mut at_millis = now_millis();
        let observed = (|| {
            let mut total = overhead.ok()?;
            for account in accounts {
                let sample = account.sample.lock().unwrap().clone()?;
                // Exceeded samples also describe the complete tree. They still
                // block their own volume, even when the aggregate fits the pool.
                let (Observation::Complete(usage) | Observation::Exceeded(usage)) =
                    sample.observation
                else {
                    return None;
                };
                total.bytes = total.bytes.checked_add(usage.bytes)?;
                total.inodes = total.inodes.checked_add(usage.inodes)?;
                at_millis = at_millis.min(sample.at_millis);
            }
            Some(total)
        })();
        let observation = match observed {
            Some(usage) if usage.bytes > self.limit.bytes => Observation::Exceeded(usage),
            Some(usage) => Observation::Complete(usage),
            None => Observation::Unavailable,
        };
        *self.sample.lock().unwrap() = Some(Sample {
            observation,
            at_millis,
            next: Instant::now(),
        });
    }

    pub fn allow_growth(&self) -> Result<(), &'static str> {
        allow_growth(&self.sample.lock().unwrap())
    }

    pub fn value(&self) -> Value {
        value(self.limit, &self.sample.lock().unwrap())
    }
}

struct Scan<'a> {
    usage: Usage,
    visited: usize,
    hardlinks: BTreeSet<(u64, u64)>,
    deadline: Instant,
    stopped: &'a AtomicBool,
}
enum Stop {
    Unavailable,
}
impl From<io::Error> for Stop {
    fn from(_: io::Error) -> Self {
        Self::Unavailable
    }
}
impl From<rustix::io::Errno> for Stop {
    fn from(_: rustix::io::Errno) -> Self {
        Self::Unavailable
    }
}

impl Scan<'_> {
    fn tick(&mut self, depth: usize) -> Result<(), Stop> {
        if depth > 64
            || self.visited >= 1_000_001
            || Instant::now() >= self.deadline
            || self.stopped.load(Ordering::SeqCst)
        {
            return Err(Stop::Unavailable);
        }
        self.visited += 1;
        Ok(())
    }

    fn count(&mut self, metadata: &Metadata) -> Result<(), Stop> {
        // Ordinary files need no retained identity. Hardlinks count once per tree,
        // but every directory entry still consumes the independent scan-work bound.
        if !metadata.is_dir() && metadata.nlink() > 1 {
            let key = (metadata.dev(), metadata.ino());
            if self.hardlinks.contains(&key) {
                return Ok(());
            }
            if self.hardlinks.len() >= 16384 {
                return Err(Stop::Unavailable);
            }
            self.hardlinks.insert(key);
        }
        self.usage.inodes = self.usage.inodes.checked_add(1).ok_or(Stop::Unavailable)?;
        self.usage.bytes = metadata
            .blocks()
            .checked_mul(512)
            .and_then(|bytes| self.usage.bytes.checked_add(bytes))
            .ok_or(Stop::Unavailable)?;
        Ok(())
    }

    fn walk(&mut self, directory: &File, depth: usize) -> Result<(), Stop> {
        if depth > 64 {
            return Err(Stop::Unavailable);
        }
        for entry in Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            self.tick(depth)?;
            let node = File::from(openat2(
                directory,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?);
            let metadata = node.metadata()?;
            self.count(&metadata)?;
            if metadata.is_dir() {
                // Reopen the held directory, not its possibly renamed entry.
                let child = File::from(openat2(
                    &node,
                    ".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
                )?);
                self.walk(&child, depth + 1)?;
            }
        }
        Ok(())
    }
}

pub fn measure(path: &Path, limit: Usage, stopped: &AtomicBool) -> Observation {
    measure_with_timeout(path, limit, stopped, Duration::from_secs(5))
}

fn measure_with_timeout(
    path: &Path,
    limit: Usage,
    stopped: &AtomicBool,
    timeout: Duration,
) -> Observation {
    let mut scan = Scan {
        usage: Usage::default(),
        visited: 0,
        hardlinks: BTreeSet::new(),
        deadline: Instant::now() + timeout,
        stopped,
    };
    let result = (|| -> Result<(), Stop> {
        scan.tick(0)?;
        let root = File::from(openat2(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?);
        scan.count(&root.metadata()?)?;
        scan.walk(&root, 1)
    })();
    match result {
        Ok(()) if Instant::now() < scan.deadline && !stopped.load(Ordering::SeqCst) => {
            if scan.usage.bytes > limit.bytes || scan.usage.inodes > limit.inodes {
                Observation::Exceeded(scan.usage)
            } else {
                Observation::Complete(scan.usage)
            }
        }
        Ok(()) => Observation::Unavailable,
        Err(Stop::Unavailable) => Observation::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsStr,
        fs,
        os::unix::{ffi::OsStrExt, fs::symlink},
        path::PathBuf,
    };

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "sandcrab-usage-{}",
                sandcrab_core::new_uuid().unwrap()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn limit() -> Usage {
        Usage {
            bytes: 16 * 1024 * 1024,
            inodes: 1024,
        }
    }

    #[test]
    fn allocated_usage_deduplicates_hardlinks_without_following_symlinks() {
        let root = Root::new();
        let outside = Root::new();
        fs::write(outside.0.join("ungranted"), vec![1; 2 * 1024 * 1024]).unwrap();
        let file = root.0.join(OsStr::from_bytes(b"non-utf8-\xff"));
        fs::write(&file, vec![1; 8192]).unwrap();
        fs::hard_link(&file, root.0.join("same-inode")).unwrap();
        symlink(&outside.0, root.0.join("outside")).unwrap();
        let sparse = root.0.join("sparse");
        File::create(&sparse)
            .unwrap()
            .set_len(8 * 1024 * 1024)
            .unwrap();
        let metadata = [root.0.clone(), file, root.0.join("outside"), sparse]
            .map(|path| fs::symlink_metadata(path).unwrap());
        let expected = Usage {
            bytes: metadata.iter().map(|m| m.blocks() * 512).sum(),
            inodes: 4,
        };
        assert_eq!(
            measure(&root.0, limit(), &AtomicBool::new(false)),
            Observation::Complete(expected)
        );
        assert_eq!(
            fs::read(outside.0.join("ungranted")).unwrap().len(),
            2 * 1024 * 1024
        );
    }

    #[test]
    fn incomplete_scans_never_report_empty_or_successful_usage() {
        let root = Root::new();
        fs::write(root.0.join("data"), vec![1; 8192]).unwrap();
        let stopped = AtomicBool::new(false);
        assert!(matches!(
            measure(
                &root.0,
                Usage {
                    bytes: 4096,
                    ..limit()
                },
                &stopped
            ),
            Observation::Exceeded(_)
        ));
        assert!(matches!(
            measure(
                &root.0,
                Usage {
                    inodes: 1,
                    ..limit()
                },
                &stopped
            ),
            Observation::Exceeded(_)
        ));
        assert_eq!(
            measure(&root.0.join("missing"), limit(), &stopped),
            Observation::Unavailable
        );
        assert_eq!(
            measure(&root.0, limit(), &AtomicBool::new(true)),
            Observation::Unavailable
        );
        assert_eq!(
            measure_with_timeout(&root.0, limit(), &stopped, Duration::ZERO),
            Observation::Unavailable
        );
        let mut directory = root.0.clone();
        for _ in 0..66 {
            directory = directory.join("nested");
            fs::create_dir(&directory).unwrap();
        }
        assert_eq!(
            measure(&root.0, limit(), &stopped),
            Observation::Unavailable
        );
    }

    #[test]
    fn pending_and_excess_usage_refuse_growth_then_recover_after_deletion() {
        let root = Root::new();
        let stopped = AtomicBool::new(false);
        let account = Account::new(
            root.0.clone(),
            Usage {
                bytes: 1024 * 1024,
                ..limit()
            },
        );
        assert!(account.pending());
        assert_eq!(account.allow_growth(), Err("STORAGE_USAGE_UNAVAILABLE"));
        assert!(account.value()["allocatedBytes"].is_null());
        fs::write(root.0.join("large"), vec![1; 2 * 1024 * 1024]).unwrap();
        account.refresh(true, &stopped);
        assert!(!account.pending());
        assert_eq!(account.allow_growth(), Err("STORAGE_LIMIT"));
        assert_eq!(account.value()["state"], "exceeded");
        fs::remove_file(root.0.join("large")).unwrap();
        account.refresh(true, &stopped);
        assert_eq!(account.allow_growth(), Ok(()));
        assert_eq!(account.value()["state"], "complete");
        account.refresh(true, &AtomicBool::new(true));
        assert_eq!(account.allow_growth(), Err("STORAGE_USAGE_UNAVAILABLE"));
        assert!(account.value()["allocatedBytes"].is_null());
    }

    #[test]
    fn pool_uses_complete_owned_samples_and_never_hides_a_missing_member() {
        let first = Root::new();
        let second = Root::new();
        fs::write(first.0.join("a"), vec![1; 8192]).unwrap();
        fs::write(first.0.join("b"), vec![1; 16384]).unwrap();
        fs::write(second.0.join("c"), vec![1; 4096]).unwrap();
        let first_account = Account::new(
            first.0.clone(),
            Usage {
                bytes: 1,
                ..limit()
            },
        );
        let second_account = Account::new(second.0.clone(), limit());
        let accounts = [&first_account, &second_account];
        let stopped = AtomicBool::new(false);
        let pool = Pool::new(16 * 1024 * 1024);
        pool.refresh(Ok(Usage::default()), accounts.into_iter());
        assert_eq!(pool.allow_growth(), Err("STORAGE_USAGE_UNAVAILABLE"));

        first_account.refresh(true, &stopped);
        second_account.refresh(true, &stopped);
        assert_eq!(first_account.allow_growth(), Err("STORAGE_LIMIT"));
        // The first volume exceeds its own bound, but its observation must
        // include both files so the pool never mistakes a prefix for its total.
        let metadata = [
            first.0.clone(),
            first.0.join("a"),
            first.0.join("b"),
            second.0.clone(),
            second.0.join("c"),
        ]
        .map(|path| fs::symlink_metadata(path).unwrap());
        let expected_bytes: u64 = metadata.iter().map(|m| m.blocks() * 512).sum();
        pool.refresh(Ok(Usage::default()), accounts.into_iter());
        assert_eq!(pool.allow_growth(), Ok(()));
        assert_eq!(pool.value()["allocatedBytes"], expected_bytes);
        assert_eq!(pool.value()["inodes"], 5);
        let oldest = accounts
            .into_iter()
            .map(|a| a.value()["observedAtMillis"].as_u64().unwrap())
            .min()
            .unwrap();
        assert_eq!(pool.value()["observedAtMillis"], oldest);

        let bounded = Pool::new(expected_bytes - 1);
        bounded.refresh(Ok(Usage::default()), accounts.into_iter());
        assert_eq!(bounded.allow_growth(), Err("STORAGE_LIMIT"));
        second_account.refresh(true, &AtomicBool::new(true));
        bounded.refresh(Ok(Usage::default()), accounts.into_iter());
        assert_eq!(bounded.allow_growth(), Err("STORAGE_USAGE_UNAVAILABLE"));
        assert!(bounded.value()["allocatedBytes"].is_null());

        // Removing an owned member changes the aggregate inventory, without
        // retaining that member's unavailable sample or its former allocation.
        bounded.refresh(Ok(Usage::default()), [&first_account].into_iter());
        assert_eq!(bounded.allow_growth(), Ok(()));
        bounded.refresh(
            Err(io::Error::other("metadata unavailable")),
            [].into_iter(),
        );
        assert_eq!(bounded.allow_growth(), Err("STORAGE_USAGE_UNAVAILABLE"));
    }

    #[test]
    fn publication_scan_waits_for_an_existing_scan_and_observes_new_data() {
        let root = Root::new();
        let account = Account::new(
            root.0.clone(),
            Usage {
                bytes: 65536,
                ..limit()
            },
        );
        account.refresh(true, &AtomicBool::new(false));
        assert_eq!(account.allow_growth(), Ok(()));
        fs::write(root.0.join("new-data"), vec![1; 131072]).unwrap();
        let in_progress = account.scanning.lock().unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let (finished, result) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let account = &account;
            scope.spawn(move || {
                started.send(()).unwrap();
                account.refresh(true, &AtomicBool::new(false));
                finished.send(account.allow_growth()).unwrap();
            });
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(
                result.recv_timeout(Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            );
            drop(in_progress);
            assert_eq!(
                result.recv_timeout(Duration::from_secs(2)).unwrap(),
                Err("STORAGE_LIMIT")
            );
        });
    }
}
