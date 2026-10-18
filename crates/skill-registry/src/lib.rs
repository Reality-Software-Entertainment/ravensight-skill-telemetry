//! Read-only discovery under an explicitly approved `skills/` directory.
//!
//! Reads only direct `skills/<directory>/SKILL.md` children, never recurses, and
//! skips all symlinks. The caller selects the source and optional namespace;
//! neither provenance nor versions are guessed from directory names.
//! Frontmatter supports top-level `name:` and `version:` plain or single/double
//! quoted scalars (without escapes); other fields and the body are never exported.
//! Missing names fall back to the directory name. Complex YAML for identity fields
//! is rejected rather than interpreted. This module executes no skill instructions.
//! Discovery assumes the approved tree is not concurrently modified by an attacker.

mod plugin;
pub use plugin::{PluginDiscovery, PluginMetadata, discover_plugin};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationSource {
    Project,
    User,
    Plugin,
    OtherLocal,
}

/// Only this allowlisted metadata may be exported. No descriptions or paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillMetadata {
    pub name: String,
    pub namespace: Option<String>,
    pub source: InstallationSource,
    pub version: Option<String>,
    pub content_digest: String,
}

/// Deliberately not serializable: paths are local-only.
#[derive(Debug)]
pub struct DiscoveredSkill {
    pub metadata: SkillMetadata,
    pub local_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub source: InstallationSource,
    pub namespace: Option<String>,
    pub max_entries: usize,
    pub max_file_bytes: usize,
}
impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            source: InstallationSource::Project,
            namespace: None,
            max_entries: 512,
            max_file_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Diagnostic {
    EntryLimit,
    SymlinkSkipped,
    InvalidDirectoryName,
    MissingSkillFile,
    InvalidFile,
    FileTooLarge,
    InvalidUtf8,
    InvalidMetadata,
    ReadFailed,
}

#[derive(Debug, Default)]
pub struct DiscoveryReport {
    pub skills: Vec<DiscoveredSkill>,
    /// Codes only; never includes document contents or untrusted filenames.
    pub diagnostics: Vec<Diagnostic>,
    /// Repeated qualified identities are retained, never silently overwritten.
    pub conflicts: Vec<String>,
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
}
fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && value != "."
        && value != ".."
}

/// Invalid limits/namespaces and inaccessible roots return errors. Bad entries
/// produce bounded, content-free diagnostics and do not prevent other discovery.
pub fn discover(root: &Path, options: &DiscoveryOptions) -> io::Result<DiscoveryReport> {
    if options.max_entries == 0
        || options.max_entries > 10_000
        || options.max_file_bytes == 0
        || options.max_file_bytes > 1024 * 1024
        || options
            .namespace
            .as_deref()
            .is_some_and(|n| !valid_namespace(n))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid discovery limits or namespace",
        ));
    }
    let root_meta = fs::symlink_metadata(root)?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "approved root must be a real directory",
        ));
    }
    let root = fs::canonicalize(root)?;
    let mut report = DiscoveryReport::default();
    for (index, entry) in fs::read_dir(&root)?.enumerate() {
        if index == options.max_entries {
            report.diagnostics.push(Diagnostic::EntryLimit);
            break;
        }
        let Ok(entry) = entry else {
            report.diagnostics.push(Diagnostic::ReadFailed);
            continue;
        };
        let Ok(kind) = entry.file_type() else {
            report.diagnostics.push(Diagnostic::ReadFailed);
            continue;
        };
        if kind.is_symlink() {
            report.diagnostics.push(Diagnostic::SymlinkSkipped);
            continue;
        }
        if !kind.is_dir() {
            continue;
        }
        let filename = entry.file_name();
        let Some(name) = filename.to_str().filter(|n| valid_name(n)) else {
            report.diagnostics.push(Diagnostic::InvalidDirectoryName);
            continue;
        };
        let path = entry.path().join("SKILL.md");
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                report
                    .diagnostics
                    .push(if e.kind() == io::ErrorKind::NotFound {
                        Diagnostic::MissingSkillFile
                    } else {
                        Diagnostic::ReadFailed
                    });
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            report.diagnostics.push(Diagnostic::SymlinkSkipped);
            continue;
        }
        if !meta.is_file() {
            report.diagnostics.push(Diagnostic::InvalidFile);
            continue;
        }
        if meta.len() > options.max_file_bytes as u64 {
            report.diagnostics.push(Diagnostic::FileTooLarge);
            continue;
        }
        let canonical = match fs::canonicalize(&path) {
            Ok(p) if p.starts_with(&root) => p,
            _ => {
                report.diagnostics.push(Diagnostic::InvalidFile);
                continue;
            }
        };
        let bytes = match read_bounded(&canonical, options.max_file_bytes) {
            Ok(b) => b,
            Err(_) => {
                report.diagnostics.push(Diagnostic::ReadFailed);
                continue;
            }
        };
        if bytes.len() > options.max_file_bytes {
            report.diagnostics.push(Diagnostic::FileTooLarge);
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            report.diagnostics.push(Diagnostic::InvalidUtf8);
            continue;
        };
        let Some((name, version)) = metadata(text, name) else {
            report.diagnostics.push(Diagnostic::InvalidMetadata);
            continue;
        };
        report.skills.push(DiscoveredSkill {
            metadata: SkillMetadata {
                name,
                namespace: options.namespace.clone(),
                source: options.source,
                version,
                content_digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
            },
            local_path: canonical,
        });
    }
    report.skills.sort_by(|a, b| {
        a.metadata
            .name
            .cmp(&b.metadata.name)
            .then(a.local_path.cmp(&b.local_path))
    });
    let mut names = BTreeSet::new();
    let mut conflicts = BTreeSet::new();
    for skill in &report.skills {
        let identity = match &skill.metadata.namespace {
            Some(ns) => format!("{ns}:{}", skill.metadata.name),
            None => skill.metadata.name.clone(),
        };
        if !names.insert(identity.clone()) {
            conflicts.insert(identity);
        }
    }
    report.conflicts = conflicts.into_iter().collect();
    Ok(report)
}

fn read_bounded(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn scalar(input: &str) -> Option<&str> {
    let input = input.trim();
    if input.starts_with('"') || input.starts_with('\'') {
        let quote = input.as_bytes()[0];
        if input.len() < 2 || input.as_bytes().last() != Some(&quote) {
            return None;
        }
        let value = &input[1..input.len() - 1];
        if value.bytes().any(|b| b == quote || b == b'\\') {
            return None;
        }
        Some(value)
    } else {
        Some(input)
    }
}
fn metadata(text: &str, directory: &str) -> Option<(String, Option<String>)> {
    let mut lines = text.lines();
    if lines.next()?.trim_end() != "---" {
        return Some((directory.to_owned(), None));
    }
    let mut name = None;
    let mut version = None;
    let mut closed = false;
    for line in lines {
        if line.trim_end() == "---" {
            closed = true;
            break;
        }
        if line.starts_with(char::is_whitespace) || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "name" => {
                if name.is_some() {
                    return None;
                }
                let value = scalar(value)?;
                if !valid_name(value) {
                    return None;
                }
                name = Some(value.to_owned());
            }
            "version" => {
                if version.is_some() {
                    return None;
                }
                let value = scalar(value)?;
                if value.is_empty()
                    || value.len() > 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
                {
                    return None;
                }
                version = Some(value.to_owned());
            }
            _ => {}
        }
    }
    closed.then(|| (name.unwrap_or_else(|| directory.to_owned()), version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    fn skill(root: &Path, dir: &str, content: &str) {
        fs::create_dir_all(root.join(dir)).unwrap();
        fs::write(root.join(dir).join("SKILL.md"), content).unwrap();
    }
    #[test]
    fn exports_only_identity_and_digest() {
        let root = TempDir::new().unwrap();
        skill(
            root.path(),
            "sample",
            "---\nname: sample\nversion: '1.2.3'\ndescription: PRIVATE_SECRET\n---\nRun secret command",
        );
        let result = discover(
            root.path(),
            &DiscoveryOptions {
                namespace: Some("vendor".into()),
                source: InstallationSource::Plugin,
                ..Default::default()
            },
        )
        .unwrap();
        let metadata = &result.skills[0].metadata;
        assert_eq!(metadata.version.as_deref(), Some("1.2.3"));
        assert_eq!(metadata.namespace.as_deref(), Some("vendor"));
        assert_eq!(metadata.content_digest.len(), 71);
        let exported = serde_json::to_string(metadata).unwrap();
        for secret in [
            "PRIVATE_SECRET",
            "Run secret command",
            root.path().to_str().unwrap(),
        ] {
            assert!(!exported.contains(secret));
        }
    }
    #[test]
    fn unknown_versions_and_duplicate_names_are_honest() {
        let root = TempDir::new().unwrap();
        skill(root.path(), "one", "---\nname: same\n---\nbody");
        skill(root.path(), "two", "---\nname: same\n---\nother");
        let result = discover(root.path(), &DiscoveryOptions::default()).unwrap();
        assert_eq!(result.skills.len(), 2);
        assert_eq!(result.conflicts, ["same"]);
        assert!(result.skills.iter().all(|s| s.metadata.version.is_none()));
        assert_ne!(
            result.skills[0].metadata.content_digest,
            result.skills[1].metadata.content_digest
        );
    }
    #[test]
    fn malformed_and_traversal_names_rejected() {
        for body in [
            "---\nname: ../../outside\n---",
            "---\nname: [one, two]\n---",
            "---\nname: one\nname: two\n---",
            "---\nname: valid",
            "---\nversion: &alias secret\n---",
        ] {
            assert!(metadata(body, "fallback").is_none(), "{body}");
        }
        assert_eq!(
            metadata("ordinary body", "fallback"),
            Some(("fallback".into(), None))
        );
    }
    #[test]
    fn limits_and_invalid_entries_are_bounded() {
        let root = TempDir::new().unwrap();
        skill(root.path(), "one", &"x".repeat(100));
        skill(root.path(), "two", "body");
        let report = discover(
            root.path(),
            &DiscoveryOptions {
                max_file_bytes: 10,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(report.skills.len(), 1);
        assert_eq!(report.diagnostics, [Diagnostic::FileTooLarge]);
        let report = discover(
            root.path(),
            &DiscoveryOptions {
                max_entries: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(report.skills.len() <= 1);
        assert!(report.diagnostics.contains(&Diagnostic::EntryLimit));
        assert!(
            discover(
                root.path(),
                &DiscoveryOptions {
                    namespace: Some("../../secret".into()),
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
    #[test]
    fn never_recurses_or_exports_invalid_utf8() {
        let root = TempDir::new().unwrap();
        skill(root.path(), "outer/inner", "nested");
        skill(root.path(), "invalid", "valid");
        fs::write(root.path().join("invalid/SKILL.md"), [0xff]).unwrap();
        let report = discover(root.path(), &DiscoveryOptions::default()).unwrap();
        assert!(report.skills.is_empty());
        assert!(report.diagnostics.contains(&Diagnostic::InvalidUtf8));
    }
    #[cfg(unix)]
    #[test]
    fn skips_symlink_roots_directories_and_files() {
        use std::os::unix::fs::symlink;
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        skill(outside.path(), "secret", "private");
        symlink(outside.path().join("secret"), root.path().join("escape")).unwrap();
        fs::create_dir(root.path().join("linked-file")).unwrap();
        symlink(
            outside.path().join("secret/SKILL.md"),
            root.path().join("linked-file/SKILL.md"),
        )
        .unwrap();
        let report = discover(root.path(), &DiscoveryOptions::default()).unwrap();
        assert!(report.skills.is_empty());
        assert_eq!(
            report.diagnostics,
            [Diagnostic::SymlinkSkipped, Diagnostic::SymlinkSkipped]
        );
        symlink(outside.path(), root.path().join("root-link")).unwrap();
        assert!(discover(&root.path().join("root-link"), &DiscoveryOptions::default()).is_err());
    }
}
