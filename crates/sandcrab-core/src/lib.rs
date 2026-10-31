#![forbid(unsafe_code)]
//! Sandbox mechanisms shared by every Sandcrab service: strict JSON, identifiers, protected
//! paths, systemd units, the shell channel, host-call mailboxes, file transfers and artifacts.
//! Nothing here knows which product requested a lease.

pub mod artifacts;
pub mod command;
pub mod fs;
pub mod http;
pub mod ids;
pub mod install;
pub mod job;
pub mod json;
pub mod mailbox;
pub mod raw;
pub mod transfer;
pub mod unit;

pub use ids::{hex, new_uuid, uuid};
pub use json::parse;
