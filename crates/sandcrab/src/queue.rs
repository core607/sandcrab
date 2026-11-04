//! Accepted commands keep their IDs and result reservations while waiting. A
//! queued outcome never authorizes replay or consumes a sandbox admission slot.
use crate::{
    config::Profile,
    service::{Registry, Request, Run, Service},
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(crate) struct Waiting {
    since: Instant,
    deadline: Instant,
}

impl Waiting {
    pub fn elapsed(self, now: Instant) -> u64 {
        now.saturating_duration_since(self.since).as_millis() as u64
    }
    pub fn expired(self, now: Instant) -> bool {
        now >= self.deadline
    }
}

pub(crate) struct Finite {
    pub request: Request,
    pub profile: Profile,
    pub timeout: u64,
    pub limit: usize,
    pub cancelled: Arc<AtomicBool>,
    pub calls: Option<Arc<crate::host_calls::Calls>>,
    pub incarnation: String,
}

impl Run {
    pub(crate) fn enqueue(&mut self, timeout: u64) {
        let now = Instant::now();
        self.waiting = Some(Waiting {
            since: now,
            deadline: now + Duration::from_millis(timeout),
        });
        self.state = "queued".into();
    }

    pub(crate) fn dispatch(&mut self, now: Instant) {
        if let Some(waiting) = self.waiting.take() {
            self.queue_wait_millis = waiting.elapsed(now);
        }
        self.state = "running".into();
    }

    pub(crate) fn unexecuted(&mut self, code: &str, cancelled: bool, now: Instant) {
        if let Some(waiting) = self.waiting.take() {
            self.queue_wait_millis = waiting.elapsed(now);
        }
        self.state = if cancelled { "cancelled" } else { "refused" }.into();
        self.result = Some(json!({"code":code,"executed":false}));
        self.completed_at = Some(now);
        if cancelled {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        if let Some(calls) = &self.calls {
            calls.close();
        }
    }
}

impl Registry {
    pub(crate) fn queued(&self) -> usize {
        self.runs
            .values()
            .filter(|run| run.waiting.is_some())
            .count()
    }

    pub(crate) fn finish_queued(&mut self, id: &str, code: &str, cancelled: bool, now: Instant) {
        let Some(run) = self.runs.get_mut(id).filter(|run| run.waiting.is_some()) else {
            return;
        };
        let incarnation = run.stream_id.clone();
        let session = run.request["sessionId"].as_str().map(str::to_owned);
        run.unexecuted(code, cancelled, now);
        // Remove the payload before the terminal record can be forgotten. A
        // caller may reuse that ID immediately; stale work must not execute it.
        self.finite_queue
            .retain(|work| work.request.id != id || work.incarnation != incarnation);
        if let Some(session) = session {
            self.remove_waiting_command(&session, id, &incarnation);
        }
        self.queue_completed.push(id.into());
    }

    pub(crate) fn expire_queue(&mut self, stopped: bool) {
        let now = Instant::now();
        let ended: Vec<_> = self
            .runs
            .iter()
            .filter_map(|(id, run)| {
                let waiting = run.waiting?;
                let cancelled = stopped || run.cancelled.load(Ordering::SeqCst);
                (cancelled || waiting.expired(now)).then(|| (id.clone(), cancelled))
            })
            .collect();
        for (id, cancelled) in ended {
            self.finish_queued(
                &id,
                if cancelled {
                    "COMMAND_CANCELLED"
                } else {
                    "QUEUE_TIMEOUT"
                },
                cancelled,
                now,
            );
        }
    }
}

impl Service {
    pub(crate) fn reap_queue(&self) {
        let completed = {
            let mut registry = self.registry.lock().unwrap();
            registry.expire_sessions();
            registry.expire_queue(self.stopped.load(Ordering::SeqCst));
            std::mem::take(&mut registry.queue_completed)
        };
        for id in completed {
            self.sdk_completed(&id);
        }
    }

    /// Called by the existing accept-loop maintenance tick. Waiting commands
    /// occupy bounded records without blocking admission handlers or adding waiters.
    pub(crate) fn dispatch_queue(self: &Arc<Self>) {
        self.reap_queue();
        loop {
            let mut registry = self.registry.lock().unwrap();
            if self.stopped.load(Ordering::SeqCst)
                || registry.active >= self.runtime.config.service.max_sandboxes
            {
                break;
            }
            let Some(work) = registry.finite_queue.pop_front() else {
                break;
            };
            let id = work.request.id.clone();
            let now = Instant::now();
            let Some(run) = registry
                .runs
                .get_mut(&id)
                .filter(|run| run.stream_id == work.incarnation && run.waiting.is_some())
            else {
                continue;
            };
            if run.cancelled.load(Ordering::SeqCst) || run.waiting.unwrap().expired(now) {
                let cancelled = run.cancelled.load(Ordering::SeqCst);
                registry.finish_queued(
                    &id,
                    if cancelled {
                        "COMMAND_CANCELLED"
                    } else {
                        "QUEUE_TIMEOUT"
                    },
                    cancelled,
                    now,
                );
                continue;
            }
            run.dispatch(now);
            registry.active += 1;
            if self.spawn_finite(work).is_err() {
                registry.active -= 1;
                registry
                    .runs
                    .get_mut(&id)
                    .unwrap()
                    .unexecuted("RUN_UNAVAILABLE", false, now);
                registry.queue_completed.push(id);
            }
        }
        self.reap_queue();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};

    fn pending() -> (Registry, String) {
        let config = crate::config::Config::parse(include_str!("../config.example.toml")).unwrap();
        let request: Request =
            serde_json::from_value(json!({"id":sandcrab_core::new_uuid().unwrap(),
            "serverId":sandcrab_core::new_uuid().unwrap(),"profile":"python","command":["true"]}))
            .unwrap();
        let id = request.id.clone();
        let mut run = Run::new(
            serde_json::to_value(&request).unwrap(),
            "python".into(),
            Arc::new(AtomicBool::new(false)),
            64,
            true,
        )
        .unwrap();
        run.enqueue(2000);
        let work = Finite {
            request,
            profile: config.profiles["python"].clone(),
            timeout: 1000,
            limit: 64,
            cancelled: run.cancelled.clone(),
            calls: run.calls.clone(),
            incarnation: run.stream_id.clone(),
        };
        (
            Registry {
                runs: BTreeMap::from([(id.clone(), run)]),
                sessions: BTreeMap::new(),
                active: 1,
                reserved: 64,
                finite_queue: VecDeque::from([work]),
                queue_completed: Vec::new(),
            },
            id,
        )
    }

    #[test]
    fn timeout_removes_payload_before_forget_and_retains_reservation_until_release() {
        let (mut registry, id) = pending();
        assert_eq!(registry.forget(&id), Err("RUN_ACTIVE"));
        let now = Instant::now();
        registry.runs.get_mut(&id).unwrap().waiting = Some(Waiting {
            since: now - Duration::from_secs(3),
            deadline: now - Duration::from_secs(1),
        });
        registry.expire_queue(false);
        assert_eq!(registry.runs[&id].state, "refused");
        assert_eq!(
            registry.runs[&id].result,
            Some(json!({"code":"QUEUE_TIMEOUT","executed":false}))
        );
        assert!(registry.runs[&id].queue_wait_millis >= 3000);
        assert!(registry.finite_queue.is_empty());
        assert_eq!(
            (registry.active, registry.reserved, registry.queued()),
            (1, 64, 0)
        );
        registry.forget(&id).unwrap();
        assert_eq!((registry.active, registry.reserved), (1, 0));
        assert!(registry.queue_completed.is_empty());
    }

    #[test]
    fn shutdown_cancels_waiters_without_releasing_an_active_sandbox() {
        let (mut registry, id) = pending();
        registry.expire_queue(true);
        assert_eq!(registry.runs[&id].state, "cancelled");
        assert_eq!(
            registry.runs[&id].result,
            Some(json!({"code":"COMMAND_CANCELLED","executed":false}))
        );
        assert!(registry.runs[&id].cancelled.load(Ordering::SeqCst));
        assert!(registry.finite_queue.is_empty());
        assert_eq!(registry.active, 1);
        registry.expire_results(
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(registry.runs.is_empty());
        assert!(registry.queue_completed.is_empty());
        assert_eq!((registry.active, registry.reserved), (1, 0));
    }

    #[test]
    fn dispatch_freezes_wait_and_ends_the_queue_deadline() {
        let (mut registry, id) = pending();
        let now = Instant::now();
        registry.runs.get_mut(&id).unwrap().waiting = Some(Waiting {
            since: now - Duration::from_millis(150),
            deadline: now + Duration::from_millis(10),
        });
        registry.runs.get_mut(&id).unwrap().dispatch(now);
        registry.expire_queue(true);
        assert_eq!(registry.runs[&id].state, "running");
        assert_eq!(registry.runs[&id].summary()["queueWaitMillis"], 150);
        assert!(!registry.runs[&id].terminal());
    }
}
