//! Strict request JSON: unique object keys, bounded nesting and preserved number tokens.
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, value::RawValue};
use std::fmt;

struct Container {
    depth: usize,
}

impl<'de> Visitor<'de> for Container {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a bounded JSON array or unique-key object")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(raw) = input.next_element::<&RawValue>()? {
            values.push(expand(raw, self.depth + 1).map_err(de::Error::custom)?);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let raw = input.next_value::<&RawValue>()?;
            values.insert(key, expand(raw, self.depth + 1).map_err(de::Error::custom)?);
        }
        Ok(Value::Object(values))
    }
}

fn expand(raw: &RawValue, depth: usize) -> Result<Value, &'static str> {
    if depth >= 128 {
        return Err("INVALID_REQUEST");
    }
    // Raw tokens keep objects distinct from serde's arbitrary-precision number map.
    // The CLI enables that feature in the shared workspace; protocol types must not change.
    if matches!(raw.get().as_bytes().first(), Some(b'{' | b'[')) {
        serde_json::Deserializer::from_str(raw.get())
            .deserialize_any(Container { depth })
            .map_err(|_| "INVALID_REQUEST")
    } else {
        serde_json::from_str(raw.get()).map_err(|_| "INVALID_REQUEST")
    }
}

pub fn parse(bytes: &[u8]) -> Result<Value, &'static str> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = <&RawValue>::deserialize(&mut deserializer).map_err(|_| "INVALID_REQUEST")?;
    deserializer.end().map_err(|_| "INVALID_REQUEST")?;
    expand(raw, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_number_features_preserve_the_wire_token_kind() {
        let value = parse(br#"{"integer":18446744073709551616,"fraction":1.0,"nested":{"$serde_json::private::Number":"1"}}"#).unwrap();
        assert!(value["integer"].is_number());
        assert_eq!(value["fraction"].as_f64(), Some(1.0));
        assert_eq!(value["fraction"].as_u64(), None);
        assert!(value["nested"].is_object());
        assert_eq!(value["nested"]["$serde_json::private::Number"], "1");
    }

    #[test]
    fn nested_duplicates_and_extra_documents_are_refused() {
        for bytes in [br#"{"x":[{"a":1,"a":2}]}"#.as_slice(), b"{} {}", b"[] null"] {
            assert!(parse(bytes).is_err());
        }
        assert!(parse(br#"{"x":[null,true,1.25,"ok"]}"#).is_ok());
    }

    #[test]
    fn recursion_is_bounded_before_container_expansion() {
        let mut raw = vec![b'['; 160];
        raw.extend_from_slice(b"0");
        raw.extend(std::iter::repeat_n(b']', 160));
        assert!(parse(&raw).is_err());
    }
}
