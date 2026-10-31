//! Bounded discovery of retained identities, without copying command output or changing lifetimes.
use crate::service::{Service, error};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const PAGE_SIZE: usize = 64;

pub fn route(service: &Service, path: &str) -> Option<(u16, Value)> {
    let (collection, query) = path
        .split_once('?')
        .map_or((path, None), |(p, q)| (p, Some(q)));
    if !["/v1/runs", "/v1/sessions"].contains(&collection) {
        return None;
    }
    let after = match query {
        None => "",
        Some(query) => match query
            .strip_prefix("after=")
            .filter(|id| sandcrab_core::uuid(id))
        {
            Some(id) => id,
            None => return Some(error(400, "INVALID_REQUEST")),
        },
    };
    let registry = service.registry.lock().unwrap();
    let value = if collection == "/v1/runs" {
        page(&service.id, &registry.runs, after)
    } else {
        page(&service.id, &registry.sessions, after)
    };
    Some((200, value))
}

fn page<T>(server_id: &str, records: &BTreeMap<String, T>, after: &str) -> Value {
    let mut entries = records.range((
        std::ops::Bound::Excluded(after.to_owned()),
        std::ops::Bound::Unbounded,
    ));
    let ids: Vec<_> = entries.by_ref().take(PAGE_SIZE).map(|(id, _)| id).collect();
    let next = entries.next().and_then(|_| ids.last().copied());
    json!({"serverId":server_id,"ids":ids,"nextAfter":next})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_stay_bounded_without_output_and_survive_cursor_record_removal() {
        let id = |n| format!("00000000-0000-4000-8000-{n:012x}");
        let mut records: BTreeMap<_, _> = (1..=66)
            .map(|n| (id(n), "private command output"))
            .collect();
        let first = page(&id(0), &records, "");
        assert_eq!(first["serverId"], id(0));
        assert_eq!(first["ids"].as_array().unwrap().len(), PAGE_SIZE);
        assert_eq!(first["ids"][0], id(1));
        assert_eq!(first["nextAfter"], id(64));
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(encoded.len() < 3000);
        assert!(!encoded.contains("private command output"));
        records.remove(&id(64));
        let last = page(&id(0), &records, &id(64));
        assert_eq!(last["ids"], json!([id(65), id(66)]));
        assert!(last["nextAfter"].is_null());
        let empty = page(&id(0), &records, &id(66));
        assert_eq!(empty["ids"], json!([]));
        assert!(empty["nextAfter"].is_null());
    }
}
