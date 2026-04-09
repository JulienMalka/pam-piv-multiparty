//! Authfile parser. JSON Lines — one object per line:
//!
//! ```jsonl
//! {"user":"alice","group":"A","spki":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."}
//! {"user":"alice","group":"B","spki":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."}
//! ```

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthfileError {
    #[error("reading authfile: {0}")]
    Io(#[from] std::io::Error),
    #[error("authfile permissions unsafe: {0}")]
    BadPerms(String),
    #[error("line {line}: {msg}")]
    ParseError { line: usize, msg: String },
    #[error("no entries for user `{0}`")]
    UserNotFound(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub group: String,
    /// DER-encoded SubjectPublicKeyInfo of the slot-9a public key the
    /// device presented at registration.
    pub spki_der: Vec<u8>,
}

#[derive(Deserialize)]
struct RawEntry {
    user: String,
    group: String,
    spki: String,
}

pub fn load_for_user(path: &Path, user: &str) -> Result<Vec<Entry>, AuthfileError> {
    let contents = check_and_read(path)?;
    parse_entries(&contents, user)
}

fn parse_entries(contents: &str, user: &str) -> Result<Vec<Entry>, AuthfileError> {
    let mut entries = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let raw: RawEntry =
            serde_json::from_str(trimmed).map_err(|e| AuthfileError::ParseError {
                line: line_no,
                msg: e.to_string(),
            })?;
        if raw.user != user {
            continue;
        }
        let spki_der =
            STANDARD
                .decode(raw.spki.as_bytes())
                .map_err(|e| AuthfileError::ParseError {
                    line: line_no,
                    msg: format!("spki is not valid base64: {e}"),
                })?;
        if spki_der.is_empty() {
            return Err(AuthfileError::ParseError {
                line: line_no,
                msg: "spki cannot be empty".into(),
            });
        }
        entries.push(Entry {
            group: raw.group,
            spki_der,
        });
    }
    if entries.is_empty() {
        return Err(AuthfileError::UserNotFound(user.to_string()));
    }
    Ok(entries)
}

fn check_and_read(path: &Path) -> Result<String, AuthfileError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let mut file = fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(AuthfileError::BadPerms(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(AuthfileError::BadPerms(format!(
            "{} must not be group- or world-writable (mode {:04o})",
            path.display(),
            meta.mode() & 0o777
        )));
    }
    if meta.uid() != 0 {
        return Err(AuthfileError::BadPerms(format!(
            "{} must be owned by root (uid 0); is owned by uid {}",
            path.display(),
            meta.uid()
        )));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    const FAKE_SPKI_B64: &str = "ZmFrZS1zcGtp";
    const FAKE_SPKI_BYTES: &[u8] = b"fake-spki";

    #[test]
    fn parses_valid_entry() {
        let entries = parse_entries(
            &format!(r#"{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}"#),
            "alice",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group, "A");
        assert_eq!(entries[0].spki_der, FAKE_SPKI_BYTES);
    }

    #[test]
    fn parses_multiple_groups_for_user() {
        let entries = parse_entries(
            &format!(
                r#"{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}
{{"user":"alice","group":"B","spki":"{FAKE_SPKI_B64}"}}"#
            ),
            "alice",
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn filters_by_user() {
        let entries = parse_entries(
            &format!(
                r#"{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}
{{"user":"bob","group":"A","spki":"{FAKE_SPKI_B64}"}}"#
            ),
            "bob",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn unknown_user_errors() {
        let err = parse_entries(
            &format!(r#"{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}"#),
            "mallory",
        )
        .unwrap_err();
        assert!(matches!(err, AuthfileError::UserNotFound(_)));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let entries = parse_entries(
            &format!(
                r#"# comment

{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}"#
            ),
            "alice",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn missing_field_errors() {
        let err = parse_entries(
            &format!(r#"{{"user":"alice","spki":"{FAKE_SPKI_B64}"}}"#),
            "alice",
        )
        .unwrap_err();
        assert!(matches!(err, AuthfileError::ParseError { .. }));
    }

    #[test]
    fn empty_spki_errors() {
        let err = parse_entries(r#"{"user":"alice","group":"A","spki":""}"#, "alice").unwrap_err();
        assert!(matches!(err, AuthfileError::ParseError { .. }));
    }

    #[test]
    fn bad_base64_errors() {
        let err = parse_entries(
            r#"{"user":"alice","group":"A","spki":"!!!not-base64!!!"}"#,
            "alice",
        )
        .unwrap_err();
        assert!(matches!(err, AuthfileError::ParseError { .. }));
    }

    #[test]
    fn malformed_json_errors() {
        let err = parse_entries("not json at all", "alice").unwrap_err();
        assert!(matches!(err, AuthfileError::ParseError { .. }));
    }

    #[test]
    fn rejects_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let f = write_tmp(&format!(
            r#"{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}"#
        ));
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o666)).unwrap();
        let err = check_and_read(f.path()).unwrap_err();
        assert!(
            matches!(&err, AuthfileError::BadPerms(m) if m.contains("writable")),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_group_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let f = write_tmp(&format!(
            r#"{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}"#
        ));
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o620)).unwrap();
        let err = check_and_read(f.path()).unwrap_err();
        assert!(
            matches!(&err, AuthfileError::BadPerms(m) if m.contains("writable")),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_non_root_owner() {
        // Skipped if running as root (e.g. in a container) since we
        // can't synthesize a non-root-owned file as root.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let f = write_tmp(&format!(
            r#"{{"user":"alice","group":"A","spki":"{FAKE_SPKI_B64}"}}"#
        ));
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o600)).unwrap();
        let err = check_and_read(f.path()).unwrap_err();
        assert!(
            matches!(&err, AuthfileError::BadPerms(m) if m.contains("root")),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_missing_file() {
        let err = check_and_read(Path::new("/nonexistent/piv-multiparty/test.map")).unwrap_err();
        assert!(matches!(err, AuthfileError::Io(_)));
    }
}
