//! A session bounds every named shell in one owned delegated subtree.
use crate::config::{Profile, invalid};
use sandcrab_core::{
    cgroup::{Cgroup, Limits},
    uuid,
};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
pub struct Group {
    pub cgroup: PathBuf,
    parent: Cgroup,
    state: Arc<Mutex<State>>,
}
enum State {
    New,
    Owned(Cgroup),
    Closed,
}

impl Group {
    pub fn new(parent: &Cgroup, id: &str) -> io::Result<Self> {
        if !uuid(id) {
            return Err(invalid("Invalid session resource identity"));
        }
        Ok(Self {
            cgroup: parent.path().join(format!("session-{id}")),
            parent: parent.clone(),
            state: Arc::new(Mutex::new(State::New)),
        })
    }

    /// Retain the group before applying limits so failed setup still has an owner.
    pub fn start(&self, profile: &Profile) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if !matches!(*state, State::New) {
            return Err(invalid("Session resource group has already been attempted"));
        }
        let name = self
            .cgroup
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("Invalid session cgroup name"))?;
        let group = match self.parent.create_child(name) {
            Ok(group) => group,
            Err(error) => {
                *state = State::Closed;
                return Err(error);
            }
        };
        *state = State::Owned(group.clone());
        group.set_limits(Limits {
            memory_bytes: profile.memory_bytes,
            tasks_max: profile.tasks_max,
            cpu_quota_percent: profile.cpu_quota_percent,
            cpu_weight: profile.cpu_weight,
            oom_group: false,
        })?;
        group.enable_children()
    }

    pub fn kernel(&self) -> io::Result<Cgroup> {
        match &*self.state.lock().unwrap() {
            State::Owned(group) => Ok(group.clone()),
            _ => Err(invalid("Session resource group is not active")),
        }
    }

    /// The file/workspace owner fences new shells and waits for their launcher
    /// handles before calling this; a failed stop retains the group and admission.
    pub fn stop(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let group = match &*state {
            State::Owned(group) => group.clone(),
            State::New | State::Closed => {
                *state = State::Closed;
                return Ok(());
            }
        };
        let mut children = Vec::new();
        for name in group.children()? {
            if !name.strip_prefix("run-").is_some_and(uuid) {
                return Err(invalid("Unexpected session cgroup child"));
            }
            let child = Cgroup::open(&group.path().join(&name))?;
            if !child.children()?.is_empty() {
                return Err(invalid("Unexpected nested sandbox cgroup"));
            }
            children.push(child);
        }
        group.kill_and_wait(Duration::from_secs(15))?;
        for child in children {
            child.remove_empty()?;
        }
        group.remove_empty()?;
        *state = State::Closed;
        Ok(())
    }
}
