//! A file request pins the session workspace until its helpers and body I/O end.
//! An uncertain cleanup keeps both that ownership and its admission reservation.
use crate::config::{Profile, invalid};
use std::{
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
}
pub struct Access {
    pub session: String,
    pub profile_name: String,
    pub profile: Profile,
    pub workspace: PathBuf,
    pub volume: Option<String>,
    pub cgroup: PathBuf,
    session_cancelled: Arc<AtomicBool>,
    state: Mutex<State>,
}
pub struct Lease {
    pub access: Arc<Access>,
    pub cancelled: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    released: bool,
}
impl Access {
    pub fn new(
        request: &crate::sessions::Open,
        profile: Profile,
        workspace: PathBuf,
        cgroup: PathBuf,
        cancelled: Arc<AtomicBool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            session: request.id.clone(),
            profile_name: request.profile.clone(),
            profile,
            workspace,
            volume: request.volume_id.clone(),
            cgroup,
            session_cancelled: cancelled,
            state: Mutex::new(State {
                closed: false,
                active: None,
                fenced: false,
            }),
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
    }
    pub fn wait(&self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let state = self.state.lock().unwrap();
            if state.fenced || Instant::now() >= deadline {
                return Err(invalid("File containment unconfirmed"));
            }
            if state.active.is_none() {
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
            sandcrab_core::unit::frozen(&self.cgroup, &self.session_cancelled, action)
        } else {
            action()
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
