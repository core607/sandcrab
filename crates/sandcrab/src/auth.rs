//! Bearer secrets are file-backed and never enter diagnostics, discovery or sandbox environments.
use crate::config::invalid;
use rustix::fs::OFlags;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use subtle::ConstantTimeEq;

pub struct Token([u8; 64]);
impl Token {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let value = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        if value.len() != 64
            || !value
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(invalid(
                "Token file must contain 64 lowercase hexadecimal bytes and an optional newline",
            ));
        }
        let mut token = [0; 64];
        token.copy_from_slice(value);
        Ok(Self(token))
    }
    pub fn authorizes(&self, header: Option<&str>) -> bool {
        let Some((scheme, value)) = header.and_then(|s| s.split_once(' ')) else {
            return false;
        };
        scheme.eq_ignore_ascii_case("bearer")
            && bool::from(self.0.as_slice().ct_eq(value.as_bytes()))
    }
    pub fn text(&self) -> &str {
        std::str::from_utf8(&self.0).expect("validated hexadecimal token")
    }
}

/// Copies may belong to root or the specified client UID. Every ancestor must be
/// protected and nonsymlink; resolving aliases first would hide writable ancestors.
pub fn read_token(path: &Path, uid: u32) -> io::Result<Token> {
    let path = std::path::absolute(path)?;
    if !sandcrab_core::fs::normal(&path) {
        return Err(invalid("Token file path must not contain parent traversal"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Token file needs a parent"))?;
    for directory in parent.ancestors() {
        let info = fs::symlink_metadata(directory)?;
        if !info.is_dir() || ![0, uid].contains(&info.uid()) || info.mode() & 0o022 != 0 {
            return Err(invalid(
                "Token file ancestors must be nonsymlink directories owned by root or the client and not writable by other accounts",
            ));
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let info = file.metadata()?;
    if !info.is_file()
        || ![0, uid].contains(&info.uid())
        || ![0o400, 0o600].contains(&(info.mode() & 0o7777))
        || info.nlink() != 1
    {
        return Err(invalid(
            "Token file must be private (mode 0400 or 0600), regular, singly linked and owned by root or the client",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(66).read_to_end(&mut bytes)?;
    Token::parse(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_are_exact_and_errors_never_repeat_the_secret() {
        let secret = "abcdef0123456789".repeat(4);
        let token = Token::parse(secret.as_bytes()).unwrap();
        assert!(token.authorizes(Some(&format!("Bearer {secret}"))));
        assert!(token.authorizes(Some(&format!("bearer {secret}"))));
        for header in [None, Some("Bearer"), Some("Bearer "), Some("Basic invalid")] {
            assert!(!token.authorizes(header));
        }
        for value in [
            format!("{secret}x"),
            format!(" {secret}"),
            secret.to_uppercase(),
            secret.replace('a', "b"),
        ] {
            assert!(!token.authorizes(Some(&format!("Bearer {value}"))));
        }
        assert!(Token::parse(format!("{secret}\n").as_bytes()).is_ok());
        let error = Token::parse(format!("{secret}\r\n").as_bytes())
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains(&secret));
    }
}
