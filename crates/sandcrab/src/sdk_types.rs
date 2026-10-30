//! Bounded OpenSandbox wire values. Host policy is never selected by a client identity.
use crate::config::Resources;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub type Result<T> = std::result::Result<T, (u16, &'static str)>;
pub const IDLE: [&str; 3] = ["tail", "-f", "/dev/null"];

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn timestamp(millis: u64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .expect("system timestamp is in the supported range")
        .format(&Rfc3339)
        .expect("UTC timestamp is representable")
}
pub fn expiration(value: &str) -> Result<u64> {
    let timestamp =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| (400, "INVALID_EXPIRATION"))?;
    let millis = u64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| (400, "INVALID_EXPIRATION"))?;
    millis
        .checked_sub(now())
        .filter(|n| *n >= 100)
        .ok_or((400, "INVALID_EXPIRATION"))
}
pub fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = sandcrab_core::parse(bytes).map_err(|_| (400, "INVALID_REQUEST"))?;
    serde_json::from_value(value).map_err(|_| (400, "INVALID_REQUEST"))
}
pub fn reply(error: (u16, &'static str)) -> (u16, Value) {
    (error.0, json!({"code":error.1,"message":error.1}))
}
pub fn native((status, value): (u16, Value)) -> Result<Value> {
    if status < 400 {
        return Ok(value);
    }
    let code = match value["error"]["code"].as_str() {
        Some("PROFILE_LIMIT") => "PROFILE_LIMIT",
        Some("PROFILE_NOT_FOUND") => "PROFILE_NOT_FOUND",
        Some("SESSION_BUSY") => "SANDBOX_BUSY",
        Some("SESSION_CAPACITY" | "RESULT_CAPACITY") => "SANDBOX_CAPACITY",
        Some("SESSION_NOT_FOUND" | "RUN_NOT_FOUND") => "NOT_FOUND",
        Some("SESSION_CHANGED") => "SANDBOX_CHANGED",
        Some("SESSION_NOT_READY" | "SESSION_CLOSED") => "SANDBOX_NOT_READY",
        Some("STOPPING") => "STOPPING",
        Some("CONTAINMENT_UNCONFIRMED") => "CONTAINMENT_UNCONFIRMED",
        _ => "NATIVE_OPERATION_FAILED",
    };
    Err((status, code))
}
pub fn strings(values: &BTreeMap<String, String>, environment: bool) -> bool {
    values.len() <= 32
        && values.iter().all(|(key, value)| {
            !key.is_empty()
                && key.len() <= 64
                && value.len() <= 1024
                && !key.contains('\0')
                && !value.contains('\0')
                && (!environment
                    || (key.bytes().enumerate().all(|(i, c)| {
                        c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                    }) && !key.starts_with("SANDBOX_")))
        })
        && values.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() <= 4096
}
fn integer(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}
pub fn memory(value: &str) -> Option<u64> {
    for (suffix, multiplier) in [
        ("Ki", 1u64 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1 << 40),
        ("k", 1000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return integer(number)?.checked_mul(multiplier);
        }
    }
    integer(value)
}
pub fn cpu(value: &str) -> Option<u64> {
    if let Some(number) = value.strip_suffix('m') {
        let milli = integer(number)?;
        return milli.is_multiple_of(10).then_some(milli / 10);
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 2 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let fraction = match fraction.len() {
        0 => 0,
        1 => integer(fraction)? * 10,
        _ => integer(fraction)?,
    };
    integer(whole)?.checked_mul(100)?.checked_add(fraction)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub uri: String,
    pub auth: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpu: String,
    pub memory: String,
}
impl ResourceLimits {
    pub fn native(&self) -> Result<Resources> {
        Ok(Resources {
            cpu_quota_percent: Some(cpu(&self.cpu).ok_or((400, "INVALID_RESOURCE_LIMIT"))?),
            memory_bytes: Some(memory(&self.memory).ok_or((400, "INVALID_RESOURCE_LIMIT"))?),
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub image: Image,
    pub entrypoint: Vec<String>,
    pub resource_limits: ResourceLimits,
    pub timeout: Option<u64>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub extensions: BTreeMap<String, String>,
    #[serde(default)]
    pub secure_access: bool,
    pub snapshot_id: Option<Value>,
    pub template_id: Option<Value>,
    pub platform: Option<Value>,
    pub resource_requests: Option<Value>,
    pub lifecycle: Option<Value>,
    pub network_policy: Option<Value>,
    pub credential_proxy: Option<Value>,
    pub volumes: Option<Value>,
}
impl Create {
    pub fn supported(&self) -> bool {
        self.image.auth.is_none()
            && self.entrypoint == IDLE
            && self.extensions.is_empty()
            && !self.secure_access
            && [
                &self.snapshot_id,
                &self.template_id,
                &self.platform,
                &self.resource_requests,
                &self.lifecycle,
                &self.network_policy,
                &self.credential_proxy,
                &self.volumes,
            ]
            .into_iter()
            .all(Option::is_none)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execute {
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub timeout: Option<u64>,
    #[serde(default)]
    pub background: bool,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    #[serde(default)]
    pub envs: BTreeMap<String, String>,
}
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub fn working_directory(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\0')
        || value.contains('$')
        || value.starts_with('~')
    {
        return Err((400, "UNSUPPORTED_WORKING_DIRECTORY"));
    }
    Ok(())
}
impl Execute {
    pub fn source(&self, environment: &BTreeMap<String, String>) -> Result<(String, String)> {
        if self.background || self.uid.is_some() || self.gid.is_some() {
            return Err((400, "UNSUPPORTED_EXECUTION_OPTION"));
        }
        if !strings(&self.envs, true) {
            return Err((400, "INVALID_ENVIRONMENT"));
        }
        let (content, command) = match (&self.command, &self.argv) {
            (Some(text), None) if !text.is_empty() && !text.contains('\0') => {
                (text.clone(), format!("/bin/bash -c {}", quote(text)))
            }
            (None, Some(argv))
                if !argv.is_empty()
                    && argv.len() <= 128
                    && !argv[0].is_empty()
                    && argv.iter().all(|v| v.len() <= 4096 && !v.contains('\0')) =>
            {
                (
                    serde_json::to_string(argv).unwrap(),
                    argv.iter().map(|v| quote(v)).collect::<Vec<_>>().join(" "),
                )
            }
            _ => return Err((400, "INVALID_COMMAND")),
        };
        let cwd = self.cwd.as_deref().unwrap_or("/workspace");
        working_directory(cwd)?;
        let mut env = environment.clone();
        env.extend(self.envs.clone());
        if !strings(&env, true) {
            return Err((400, "INVALID_ENVIRONMENT"));
        }
        let values = env
            .iter()
            .map(|(k, v)| quote(&format!("{k}={v}")))
            .collect::<Vec<_>>()
            .join(" ");
        let source = format!("(cd -- {} && exec env -- {values} {command})", quote(cwd));
        if source.len() > 16384 {
            return Err((400, "COMMAND_LIMIT"));
        }
        Ok((content, source))
    }
}

pub fn decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = bytes.get(i + 1..i + 3).ok_or((400, "INVALID_QUERY"))?;
                let pair = std::str::from_utf8(pair).map_err(|_| (400, "INVALID_QUERY"))?;
                result.push(u8::from_str_radix(pair, 16).map_err(|_| (400, "INVALID_QUERY"))?);
                i += 3;
            }
            b'+' => {
                result.push(b' ');
                i += 1;
            }
            b => {
                result.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(result).map_err(|_| (400, "INVALID_QUERY"))
}
pub fn query(value: &str) -> Result<Vec<(String, String)>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() > 4096 {
        return Err((400, "INVALID_QUERY"));
    }
    let pairs = value
        .split('&')
        .map(|v| {
            let (key, value) = v.split_once('=').ok_or((400, "INVALID_QUERY"))?;
            Ok((decode(key)?, decode(value)?))
        })
        .collect::<Result<Vec<_>>>()?;
    if pairs.len() > 32 {
        return Err((400, "INVALID_QUERY"));
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_null_sdk_defaults_do_not_enable_unsupported_options() {
        let mut request = json!({"image":{"uri":"python","auth":null},
            "entrypoint":IDLE,"resourceLimits":{"cpu":"0.25","memory":"32Mi"},
            "timeout":60,"env":{},"metadata":{},"extensions":{},"secureAccess":false,
            "snapshotId":null,"templateId":null,"platform":null,"resourceRequests":null,
            "lifecycle":null,"networkPolicy":null,"credentialProxy":null,"volumes":null});
        let parsed: Create = parse(&serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(parsed.supported());
        for name in [
            "snapshotId",
            "templateId",
            "platform",
            "resourceRequests",
            "lifecycle",
            "networkPolicy",
            "credentialProxy",
            "volumes",
        ] {
            request[name] = json!({});
            let parsed: Create = parse(&serde_json::to_vec(&request).unwrap()).unwrap();
            assert!(!parsed.supported(), "{name}");
            request[name] = Value::Null;
        }
        request["unrecognized"] = Value::Null;
        assert!(parse::<Create>(&serde_json::to_vec(&request).unwrap()).is_err());
    }
    #[test]
    fn quantities_and_queries_do_not_round_or_accept_ambiguous_values() {
        assert_eq!(cpu("250m"), Some(25));
        assert_eq!(cpu("0.25"), Some(25));
        assert_eq!(cpu("1"), Some(100));
        assert_eq!(cpu("1m"), None);
        assert_eq!(memory("32Mi"), Some(33554432));
        assert_eq!(memory("32M"), Some(32000000));
        assert_eq!(memory("18446744073709551615Gi"), None);
        assert_eq!(decode("a%2Bb+c").unwrap(), "a+b c");
        assert!(decode("%xx").is_err());
    }
    #[test]
    fn command_arguments_are_literal_and_do_not_change_the_parent_shell() {
        let input: Execute =
            parse(br#"{"argv":["printf","%s","a'; touch /tmp/escape; '"]}"#).unwrap();
        let (_, source) = input.source(&BTreeMap::new()).unwrap();
        assert!(source.starts_with("(cd -- '/workspace' && exec env -- "));
        assert!(source.ends_with("'a'\\''; touch /tmp/escape; '\\''')"));
        assert!(parse::<Execute>(br#"{"command":"true","mounts":["/"]}"#).is_err());
    }
}
