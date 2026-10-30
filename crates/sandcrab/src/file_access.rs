//! A file request pins the session workspace until its helpers and body I/O end.
//! An uncertain cleanup keeps both that ownership and its admission reservation.
use crate::config::{Profile, invalid};
use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct State {
    closed: bool,
    active: Option<Arc<AtomicBool>>,
    fenced: bool,
    shells: BTreeMap<String, Arc<AtomicBool>>,
}
pub struct Access {
    pub session: String,
    pub profile_name: String,
    pub profile: Profile,
    pub workspace: PathBuf,
    pub volume: Option<String>,
    pub resources: crate::session_resources::Group,
    session_cancelled: Arc<AtomicBool>,
    state: Mutex<State>,
}
pub struct Lease {
    pub access: Arc<Access>,
    pub cancelled: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    released: bool,
}
/// A child unit pins the shared workspace until its own containment is confirmed.
pub struct ShellLease {
    pub access: Arc<Access>,
    id: String,
    released: bool,
}
impl Access {
    pub fn new(
        request: &crate::sessions::Open,
        profile: Profile,
        workspace: PathBuf,
        resources: crate::session_resources::Group,
        cancelled: Arc<AtomicBool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            session: request.id.clone(),
            profile_name: request.profile.clone(),
            profile,
            workspace,
            volume: request.volume_id.clone(),
            resources,
            session_cancelled: cancelled,
            state: Mutex::new(State {
                closed: false,
                active: None,
                fenced: false,
                shells: BTreeMap::new(),
            }),
        })
    }
    pub fn shell(
        self: &Arc<Self>,
        id: &str,
        cancelled: Arc<AtomicBool>,
    ) -> Result<ShellLease, &'static str> {
        let mut state = self.state.lock().unwrap();
        if state.closed || state.fenced || self.session_cancelled.load(Ordering::SeqCst) {
            return Err("SESSION_ENDED");
        }
        if state.shells.contains_key(id) {
            return Err("ID_CONFLICT");
        }
        state.shells.insert(id.into(), cancelled);
        Ok(ShellLease {
            access: self.clone(),
            id: id.into(),
            released: false,
        })
    }
    pub fn acquire(
        self: &Arc<Self>,
        count: Arc<AtomicUsize>,
        limit: usize,
    ) -> Result<Lease, &'static str> {
        let mut state = self.state.lock().unwrap();
        if state.closed || self.session_cancelled.load(Ordering::SeqCst) {
            return Err("SESSION_ENDED");
        }
        if state.fenced {
            return Err("FILE_CLEANUP_UNCONFIRMED");
        }
        if state.active.is_some() {
            return Err("SESSION_FILES_BUSY");
        }
        count
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < limit).then_some(n + 1)
            })
            .map_err(|_| "FILE_CAPACITY")?;
        let cancelled = Arc::new(AtomicBool::new(false));
        state.active = Some(cancelled.clone());
        Ok(Lease {
            access: self.clone(),
            cancelled,
            count,
            released: false,
        })
    }
    pub fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        if let Some(flag) = &state.active {
            flag.store(true, Ordering::SeqCst);
        }
        for flag in state.shells.values() {
            flag.store(true, Ordering::SeqCst);
        }
    }
    pub fn wait(&self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let state = self.state.lock().unwrap();
            if state.fenced || Instant::now() >= deadline {
                return Err(invalid("File containment unconfirmed"));
            }
            if state.active.is_none() && state.shells.is_empty() {
                return Ok(());
            }
            drop(state);
            thread::sleep(Duration::from_millis(20));
        }
    }
    pub fn frozen<T>(
        &self,
        enabled: bool,
        action: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        if enabled {
            sandcrab_core::unit::frozen(&self.resources.cgroup, &self.session_cancelled, action)
        } else {
            action()
        }
    }
}
impl ShellLease {
    pub fn finish(mut self, contained: bool) {
        if contained {
            self.access.state.lock().unwrap().shells.remove(&self.id);
            self.released = true;
        }
    }
}
impl Drop for ShellLease {
    fn drop(&mut self) {
        if !self.released {
            self.access.state.lock().unwrap().fenced = true;
            self.access.session_cancelled.store(true, Ordering::SeqCst);
            self.access.stop();
        }
    }
}
impl Lease {
    pub fn finish(mut self, contained: bool) {
        if contained {
            let mut state = self.access.state.lock().unwrap();
            if state
                .active
                .as_ref()
                .is_some_and(|a| Arc::ptr_eq(a, &self.cancelled))
            {
                state.active = None;
                self.count.fetch_sub(1, Ordering::SeqCst);
                self.released = true;
            }
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.released {
            self.cancelled.store(true, Ordering::SeqCst);
            self.access.state.lock().unwrap().fenced = true;
            self.access.session_cancelled.store(true, Ordering::SeqCst);
        }
    }
}
