//! Capability views keep API discovery bounded as the complete contract grows.
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn references(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref" {
                    found.insert(value.as_str().expect("bundled reference").into());
                } else {
                    references(value, found);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                references(value, found);
            }
        }
        _ => (),
    }
}
pub fn document(capability: Option<&str>) -> Value {
    let mut document: Value =
        serde_json::from_str(include_str!("../openapi.json")).expect("bundled OpenAPI");
    let Some(capability) = capability else {
        return document;
    };
    let prefix = format!("/v1/{capability}");
    document["paths"]
        .as_object_mut()
        .unwrap()
        .retain(|path, _| {
            path == "/v1/info"
                || path == "/v1/openapi"
                || path == &prefix
                || path.starts_with(&format!("{prefix}/"))
        });
    let source = document["components"].take();
    document["components"] = json!({});
    let mut pending = BTreeSet::new();
    references(&document, &mut pending);
    let mut seen = BTreeSet::new();
    while let Some(reference) = pending.pop_first() {
        if !seen.insert(reference.clone()) {
            continue;
        }
        let pointer = reference
            .strip_prefix("#/components")
            .expect("local bundled reference");
        let value = source
            .pointer(pointer)
            .expect("resolved bundled reference")
            .clone();
        references(&value, &mut pending);
        let (category, name) = pointer.trim_start_matches('/').split_once('/').unwrap();
        if document["components"].get(category).is_none() {
            document["components"][category] = json!({});
        }
        document["components"][category][name] = value;
    }
    document
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_views_are_bounded_and_resolve_every_reference() {
        for capability in ["runs", "sessions", "volumes"] {
            let document = document(Some(capability));
            assert!(document["paths"].get(format!("/v1/{capability}")).is_some());
            assert!(serde_json::to_vec(&document).unwrap().len() < 18000);
            let mut found = BTreeSet::new();
            references(&document, &mut found);
            for reference in found {
                assert!(
                    document
                        .pointer(reference.strip_prefix('#').unwrap())
                        .is_some(),
                    "{reference}"
                );
            }
            for other in ["runs", "sessions", "volumes"] {
                if other != capability {
                    assert!(document["paths"].get(format!("/v1/{other}")).is_none());
                }
            }
        }
    }
}
