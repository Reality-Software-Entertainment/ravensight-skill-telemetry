//! Read-only Claude plugin manifest projection; no cache-index or marketplace assumptions.
use super::*;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginMetadata {
    pub name: String,
    pub version: Option<String>,
    /// A manifest claim, never a marketplace signature or enabled-installation attestation.
    pub manifest_digest: String,
}
#[derive(Debug)]
pub struct PluginDiscovery {
    pub plugin: PluginMetadata,
    pub report: DiscoveryReport,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported or unsafe plugin manifest",
    )
}
fn within(root: &Path, relative: &Path) -> io::Result<PathBuf> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        match component {
            std::path::Component::CurDir => (),
            std::path::Component::Normal(part) => {
                path.push(part);
                if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
    }
    if !path.canonicalize()?.starts_with(root) {
        return Err(invalid());
    }
    Ok(path)
}
/// Only an explicitly approved plugin directory is read. Requires its documented manifest.
/// Missing/unsupported manifests fail closed; installation/cache directories are never guessed.
pub fn discover_plugin(root: &Path, options: &DiscoveryOptions) -> io::Result<PluginDiscovery> {
    if options.max_entries == 0
        || options.max_entries > 10_000
        || options.max_file_bytes == 0
        || options.max_file_bytes > 1024 * 1024
    {
        return Err(invalid());
    }
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(invalid());
    }
    let root = root.canonicalize()?;
    let path = within(&root, Path::new(".claude-plugin/plugin.json"))?;
    if !fs::metadata(&path)?.is_file() || fs::metadata(&path)?.len() > 65536 {
        return Err(invalid());
    }
    let bytes = read_bounded(&path, 65536)?;
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let name = manifest
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| valid_name(s))
        .ok_or_else(invalid)?
        .to_owned();
    let version = match manifest.get("version") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
                })
                .ok_or_else(invalid)?
                .to_owned(),
        ),
    };
    let mut paths = vec![];
    if root.join("skills").exists() {
        paths.push("skills".to_owned());
    }
    if let Some(custom) = manifest.get("skills") {
        match custom {
            serde_json::Value::String(s) => paths.push(s.clone()),
            serde_json::Value::Array(items) if items.len() <= 16 => {
                for item in items {
                    paths.push(item.as_str().ok_or_else(invalid)?.to_owned());
                }
            }
            _ => return Err(invalid()),
        }
    } else if paths.is_empty() && root.join("SKILL.md").exists() {
        paths.push(".".into());
    }
    if paths.len() > 17 {
        return Err(invalid());
    }
    let options = DiscoveryOptions {
        source: InstallationSource::Plugin,
        namespace: Some(name.clone()),
        ..options.clone()
    };
    let mut report = DiscoveryReport::default();
    let mut seen_paths = BTreeSet::new();
    for relative in paths {
        if relative.len() > 512 {
            return Err(invalid());
        }
        let path = within(&root, Path::new(&relative))?;
        if !path.is_dir() {
            return Err(invalid());
        }
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        let remaining = options
            .max_entries
            .saturating_sub(report.skills.len() + report.diagnostics.len());
        if remaining == 0 {
            report.diagnostics.push(Diagnostic::EntryLimit);
            break;
        }
        let single = path.join("SKILL.md");
        if single.exists() {
            let single = within(&root, single.strip_prefix(&root).map_err(|_| invalid())?)?;
            if !fs::metadata(&single)?.is_file()
                || fs::metadata(&single)?.len() > options.max_file_bytes as u64
            {
                return Err(invalid());
            }
            let body = read_bounded(&single, options.max_file_bytes)?;
            if body.len() > options.max_file_bytes {
                return Err(invalid());
            }
            let text = std::str::from_utf8(&body).map_err(|_| invalid())?;
            let fallback = path
                .file_name()
                .and_then(|s| s.to_str())
                .filter(|s| valid_name(s))
                .unwrap_or(&name);
            let (skill_name, skill_version) = metadata(text, fallback).ok_or_else(invalid)?;
            report.skills.push(DiscoveredSkill {
                metadata: SkillMetadata {
                    name: skill_name,
                    namespace: Some(name.clone()),
                    source: InstallationSource::Plugin,
                    version: skill_version,
                    content_digest: format!("sha256:{:x}", Sha256::digest(&body)),
                },
                local_path: single,
            });
        } else {
            let mut child = discover(
                &path,
                &DiscoveryOptions {
                    max_entries: remaining,
                    ..options.clone()
                },
            )?;
            report.skills.append(&mut child.skills);
            report.diagnostics.append(&mut child.diagnostics);
        }
    }
    report
        .skills
        .sort_by(|a, b| a.local_path.cmp(&b.local_path));
    report.skills.dedup_by(|a, b| a.local_path == b.local_path);
    let mut names = BTreeSet::new();
    let mut conflicts = BTreeSet::new();
    for skill in &report.skills {
        let qualified = format!("{}:{}", name, skill.metadata.name);
        if !names.insert(qualified.clone()) {
            conflicts.insert(qualified);
        }
    }
    report.conflicts = conflicts.into_iter().collect();
    Ok(PluginDiscovery {
        plugin: PluginMetadata {
            name,
            version,
            manifest_digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
        },
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(root: &Path, value: serde_json::Value) {
        fs::create_dir_all(root.join(".claude-plugin")).unwrap();
        fs::write(
            root.join(".claude-plugin/plugin.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }
    fn skill(root: &Path, path: &str, name: &str) {
        fs::create_dir_all(root.join(path)).unwrap();
        fs::write(
            root.join(path).join("SKILL.md"),
            format!("---\nname: {name}\n---\nPRIVATE_BODY"),
        )
        .unwrap();
    }
    #[test]
    fn projects_manifest_claims_without_executing_or_exporting_content() {
        let t = tempfile::tempdir().unwrap();
        manifest(
            t.path(),
            serde_json::json!({"name":"example-plugin","version":"1.2.3","skills":["./extra"],"hooks":{"SessionStart":"SECRET_COMMAND"},"description":"PRIVATE_DESCRIPTION"}),
        );
        skill(t.path(), "skills/default", "default");
        skill(t.path(), "extra/custom", "custom");
        let d = discover_plugin(t.path(), &Default::default()).unwrap();
        assert_eq!(d.report.skills.len(), 2);
        assert_eq!(d.plugin.version.as_deref(), Some("1.2.3"));
        assert!(
            d.report
                .skills
                .iter()
                .all(
                    |s| s.metadata.namespace.as_deref() == Some("example-plugin")
                        && s.metadata.version.is_none()
                )
        );
        let out = serde_json::to_string(&d.plugin).unwrap();
        assert!(!out.contains("SECRET"));
        assert!(!out.contains("PRIVATE"));
        assert!(!out.contains(t.path().to_str().unwrap()));
    }
    #[test]
    fn single_skill_and_conflicts_are_explicit_and_bounded() {
        let t = tempfile::tempdir().unwrap();
        manifest(t.path(), serde_json::json!({"name":"plugin"}));
        skill(t.path(), ".", "root-skill");
        assert_eq!(
            discover_plugin(t.path(), &Default::default())
                .unwrap()
                .report
                .skills
                .len(),
            1
        );
        fs::remove_file(t.path().join("SKILL.md")).unwrap();
        skill(t.path(), "skills/first", "same");
        skill(t.path(), "skills/second", "same");
        let d = discover_plugin(t.path(), &Default::default()).unwrap();
        assert_eq!(d.report.conflicts, ["plugin:same"]);
        assert!(
            discover_plugin(
                t.path(),
                &DiscoveryOptions {
                    max_entries: 0,
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert_eq!(
            discover_plugin(
                t.path(),
                &DiscoveryOptions {
                    max_entries: 1,
                    ..Default::default()
                }
            )
            .unwrap()
            .report
            .skills
            .len(),
            1
        );
    }
    #[test]
    fn rejects_escape_absolute_paths_malformed_manifest_and_large_files() {
        let t = tempfile::tempdir().unwrap();
        for path in ["../outside", "/tmp"] {
            manifest(t.path(), serde_json::json!({"name":"plugin","skills":path}));
            assert!(discover_plugin(t.path(), &Default::default()).is_err());
        }
        manifest(t.path(), serde_json::json!({"name":"bad plugin"}));
        assert!(discover_plugin(t.path(), &Default::default()).is_err());
        fs::write(
            t.path().join(".claude-plugin/plugin.json"),
            "x".repeat(65537),
        )
        .unwrap();
        assert!(discover_plugin(t.path(), &Default::default()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_components_never_leave_selected_plugin() {
        let t = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        manifest(
            t.path(),
            serde_json::json!({"name":"plugin","skills":"linked/skills"}),
        );
        fs::create_dir(outside.path().join("skills")).unwrap();
        std::os::unix::fs::symlink(outside.path(), t.path().join("linked")).unwrap();
        assert!(discover_plugin(t.path(), &Default::default()).is_err());
    }
}
