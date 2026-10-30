//! Filename globs compile inside the bounded file helper and never resolve paths.
use crate::config::invalid;
use regex::{Regex, RegexBuilder};
use std::io;

pub struct Glob {
    regex: Regex,
    inverted: bool,
}
fn literal(value: char) -> String {
    regex::escape(&value.to_string())
}
fn atom(chars: &[char], index: &mut usize) -> io::Result<char> {
    let mut value = *chars.get(*index).ok_or_else(|| invalid("INVALID_GLOB"))?;
    *index += 1;
    if value == '\\' {
        value = *chars.get(*index).ok_or_else(|| invalid("INVALID_GLOB"))?;
        *index += 1;
    }
    Ok(value)
}
fn class(chars: &[char], index: &mut usize) -> io::Result<String> {
    let negated = chars.get(*index).is_some_and(|c| matches!(c, '!' | '^'));
    if negated {
        *index += 1;
    }
    let start = *index;
    let mut result = if negated { "[^" } else { "[" }.to_owned();
    while chars.get(*index).is_some_and(|c| *c != ']') {
        let from = atom(chars, index)?;
        result.push_str(&format!(r"\x{{{:x}}}", from as u32));
        if chars.get(*index) == Some(&'-') && chars.get(*index + 1).is_some_and(|c| *c != ']') {
            *index += 1;
            let to = atom(chars, index)?;
            if from > to {
                return Err(invalid("INVALID_GLOB"));
            }
            result.push('-');
            result.push_str(&format!(r"\x{{{:x}}}", to as u32));
        }
    }
    if *index == start || chars.get(*index) != Some(&']') {
        return Err(invalid("INVALID_GLOB"));
    }
    *index += 1;
    result.push(']');
    Ok(result)
}
fn expression(pattern: &str) -> io::Result<String> {
    let chars = pattern.chars().collect::<Vec<_>>();
    let (mut index, mut depth) = (0, 0);
    let mut result = String::from(r"\A(?:");
    while index < chars.len() {
        let value = chars[index];
        index += 1;
        match value {
            '*' => {
                let start = index - 1;
                while chars.get(index) == Some(&'*') {
                    index += 1;
                }
                if index - start >= 2
                    && (start == 0 || chars[start - 1] == '/')
                    && chars.get(index) == Some(&'/')
                {
                    result.push_str("(?:.*/)?");
                    index += 1;
                } else {
                    result.push_str("[^/]*");
                }
            }
            '/' if chars[index..] == ['*', '*'] => {
                result.push_str("(?:/.*)?");
                index += 2;
            }
            '?' => result.push_str("[^/]"),
            '[' => result.push_str(&class(&chars, &mut index)?),
            '{' => {
                depth += 1;
                if depth > 16 {
                    return Err(invalid("GLOB_LIMIT"));
                }
                result.push_str("(?:");
            }
            '}' => {
                if depth == 0 {
                    return Err(invalid("INVALID_GLOB"));
                }
                depth -= 1;
                result.push(')');
            }
            ',' if depth > 0 => result.push('|'),
            '\\' => {
                let next = *chars.get(index).ok_or_else(|| invalid("INVALID_GLOB"))?;
                index += 1;
                result.push_str(&literal(next));
            }
            '!' => return Err(invalid("UNSUPPORTED_GLOB_NEGATION")),
            value => result.push_str(&literal(value)),
        }
    }
    if depth != 0 {
        return Err(invalid("INVALID_GLOB"));
    }
    result.push_str(r")\z");
    Ok(result)
}
fn negated(pattern: &str) -> io::Result<Option<&str>> {
    if !pattern.starts_with("!(") {
        return Ok(None);
    }
    let (mut depth, mut escaped, mut class) = (0usize, false, false);
    for (index, value) in pattern.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if value == '\\' {
            escaped = true;
            continue;
        }
        if value == '[' {
            class = true;
        }
        if value == ']' {
            class = false;
        }
        if class {
            continue;
        }
        if value == '(' {
            depth += 1;
        }
        if value == ')' {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| invalid("INVALID_GLOB"))?;
            if depth == 0 {
                return Ok((index + 1 == pattern.len()).then_some(&pattern[2..index]));
            }
        }
    }
    Err(invalid("INVALID_GLOB"))
}
impl Glob {
    pub fn new(mut pattern: &str) -> io::Result<Self> {
        if pattern.is_empty() || pattern.len() > 1024 || pattern.chars().any(char::is_control) {
            return Err(invalid("GLOB_LIMIT"));
        }
        let mut inverted = false;
        let mut levels = 0;
        while let Some(inner) = negated(pattern)? {
            levels += 1;
            if levels > 8 {
                return Err(invalid("GLOB_LIMIT"));
            }
            inverted = !inverted;
            pattern = inner;
        }
        let regex = RegexBuilder::new(&expression(pattern)?)
            .size_limit(1_048_576)
            .dfa_size_limit(524_288)
            .nest_limit(32)
            .build()
            .map_err(|_| invalid("INVALID_GLOB"))?;
        Ok(Self { regex, inverted })
    }
    pub fn matches(&self, name: &str) -> bool {
        self.regex.is_match(name) != self.inverted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn globs_match_unicode_names_alternatives_escapes_and_whole_name_negation() {
        for (pattern, name, expected) in [
            ("*.txt", "note.txt", true),
            ("**/*.txt", "note.txt", true),
            ("src/*.txt", "note.txt", false),
            ("?.txt", "中.txt", true),
            ("[a-z]?.{rs,go}", "a中.rs", true),
            ("[!a-z]*", "中.go", true),
            ("[^a-z]*", "abc", false),
            (r"a\*.txt", "a*.txt", true),
            ("{,a}b", "b", true),
            ("*{a,{b,c}}", "namec", true),
            ("!(a.txt)", "b.txt", true),
            ("!(a.txt)", "a.txt", false),
            ("!({a,b}.txt)", "b.txt", false),
            ("x/**", "x", true),
            ("a$().txt", "a$().txt", true),
            (r"[a\-z]", "m", false),
            ("[a&&b]", "&", true),
        ] {
            assert_eq!(
                Glob::new(pattern).unwrap().matches(name),
                expected,
                "{pattern} {name}"
            );
        }
        for bad in ["[", "{a,b", "a}", "[z-a]", "a\\", "a!(b)", "!(a)b)"] {
            assert!(Glob::new(bad).is_err(), "{bad}");
        }
    }
}
