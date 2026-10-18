//! Observe a narrow set of Claude hook signals. Never interpret tool output as a skill result.
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use telemetry_core::{Activity, Event, Evidence, Identity, Outcome, Stage, valid_name};

pub const MAX_INPUT: usize = 256 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("input exceeds size limit")]
    TooLarge,
    #[error("invalid hook input")]
    Invalid,
    #[error("project not approved")]
    OutsideProject,
    #[error("local input error")]
    Io(#[from] std::io::Error),
}
/// Raw payloads are ephemeral; never log or persist this value or parse errors.
#[derive(Deserialize)]
struct Hook {
    hook_event_name: String,
    session_id: String,
    cwd: String,
    tool_name: Option<String>,
    agent_id: Option<String>,
    tool_use_id: Option<String>,
    tool_input: Option<SkillInput>,
}
#[derive(Deserialize)]
struct SkillInput {
    skill: Option<String>,
}

pub fn bounded_input(reader: impl Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INPUT {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

pub struct Adapter {
    identity: Identity,
    root: PathBuf,
    source_version: String,
    run_id: Option<String>,
}
impl Adapter {
    pub fn new(root: &Path, identity: Identity, source_version: &str) -> Result<Self, Error> {
        let root = root.canonicalize()?;
        if !root.is_dir() || !valid_name(source_version) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            identity,
            root,
            source_version: source_version.into(),
            run_id: None,
        })
    }
    /// Caller-owned launcher identity, stable across hook retries and unique per process launch.
    /// Never populate this from receipt time or a guessed transcript lifecycle boundary.
    pub fn with_run_id(mut self, run_id: &str) -> Result<Self, Error> {
        if !valid_name(run_id) {
            return Err(Error::Invalid);
        }
        self.run_id = Some(run_id.to_owned());
        Ok(self)
    }
    /// Conversation correlation independent of an optional explicit launcher run identity.
    /// Returned identifiers are installation-keyed; raw runtime IDs never leave this API.
    pub fn conversation_id(&self, cwd: &str, session: &str) -> Result<String, Error> {
        let (project, _) = self.scope(cwd, session)?;
        Ok(self.identity.id("session", &[&project, session]))
    }
    fn scope(&self, cwd: &str, session: &str) -> Result<(String, String), Error> {
        if session.is_empty() || session.len() > 256 {
            return Err(Error::Invalid);
        }
        if !Path::new(cwd).canonicalize()?.starts_with(&self.root) {
            return Err(Error::OutsideProject);
        }
        let project = self.identity.id("project", &[&self.root.to_string_lossy()]);
        let session = match &self.run_id {
            Some(run) => self.identity.id("session-run", &[&project, session, run]),
            None => self.identity.id("session", &[&project, session]),
        };
        Ok((project, session))
    }
    /// Ordinary tools and all their content are dropped. Skill arguments and responses are ignored.
    pub fn observe(&self, input: &[u8], received_ms: i64) -> Result<Option<Event>, Error> {
        if input.len() > MAX_INPUT {
            return Err(Error::TooLarge);
        }
        let raw: Hook = serde_json::from_slice(input).map_err(|_| Error::Invalid)?;
        let (project_id, session_id) = self.scope(&raw.cwd, &raw.session_id)?;
        let (activity, skill, invocation_id) = match raw.hook_event_name.as_str() {
            "SessionStart" => (Activity::SessionStarted, None, None),
            "SessionEnd" => (Activity::SessionEnded, None, None),
            "PreToolUse" | "PostToolUse" | "PostToolUseFailure"
                if raw.tool_name.as_deref() == Some("Skill") =>
            {
                let skill = raw
                    .tool_input
                    .and_then(|i| i.skill)
                    .filter(|s| valid_name(s))
                    .ok_or(Error::Invalid)?;
                let tool = raw
                    .tool_use_id
                    .filter(|s| !s.is_empty() && s.len() <= 256)
                    .ok_or(Error::Invalid)?;
                let id = if let Some(agent) = raw.agent_id.as_deref() {
                    if agent.is_empty() || agent.len() > 256 {
                        return Err(Error::Invalid);
                    }
                    self.identity
                        .id("agent-invocation", &[&session_id, agent, &tool])
                } else {
                    self.identity.id("invocation", &[&session_id, &tool])
                };
                let activity = match raw.hook_event_name.as_str() {
                    "PreToolUse" => Activity::Invoked,
                    "PostToolUse" => Activity::InstructionsLoaded,
                    _ => Activity::InvocationFailed,
                };
                (activity, Some(skill), Some(id))
            }
            _ => return Ok(None),
        };
        // Tool IDs deduplicate hook deliveries; receipt time is intentionally excluded.
        // SessionEnd is one observed closure per session; it never closes a skill as successful.
        let event_id = self.identity.id(
            "hook-event",
            &[
                &session_id,
                invocation_id.as_deref().unwrap_or(""),
                &raw.hook_event_name,
            ],
        );
        let e = Event {
            schema_version: 1,
            event_id,
            project_id,
            session_id,
            invocation_id,
            skill,
            source_version: self.source_version.clone(),
            received_ms,
            evidence: Evidence::Observed,
            activity,
        };
        e.validate().map_err(|_| Error::Invalid)?;
        Ok(Some(e))
    }
    /// Explicit producer claims. IDs identify the report and allow retry deduplication.
    /// No outcome is inferred from Claude's prose or command output.
    pub fn report(&self, input: &[u8], received_ms: i64) -> Result<Event, Error> {
        if input.len() > MAX_INPUT {
            return Err(Error::TooLarge);
        }
        let r: Report = serde_json::from_slice(input).map_err(|_| Error::Invalid)?;
        if !valid_name(&r.skill)
            || !valid_name(&r.report_id)
            || r.invocation_id.is_empty()
            || r.invocation_id.len() > 256
        {
            return Err(Error::Invalid);
        }
        let (project_id, session_id) = self.scope(&r.cwd, &r.session_id)?;
        let invocation_id = if let Some(agent) = r.agent_id.as_deref() {
            if agent.is_empty() || agent.len() > 256 {
                return Err(Error::Invalid);
            }
            self.identity
                .id("agent-invocation", &[&session_id, agent, &r.invocation_id])
        } else {
            self.identity
                .id("invocation", &[&session_id, &r.invocation_id])
        };
        let event_id = self
            .identity
            .id("producer-event", &[&invocation_id, &r.report_id]);
        let activity = match r.result {
            ReportResult::Stage { stage } => Activity::StageReported { stage },
            ReportResult::Outcome {
                outcome,
                checks_passed,
                checks_failed,
            } => Activity::OutcomeReported {
                outcome,
                checks_passed,
                checks_failed,
            },
        };
        let e = Event {
            schema_version: 1,
            event_id,
            project_id,
            session_id,
            invocation_id: Some(invocation_id),
            skill: Some(r.skill),
            source_version: self.source_version.clone(),
            received_ms,
            evidence: Evidence::Reported,
            activity,
        };
        e.validate().map_err(|_| Error::Invalid)?;
        Ok(e)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    session_id: String,
    cwd: String,
    invocation_id: String,
    report_id: String,
    agent_id: Option<String>,
    skill: String,
    result: ReportResult,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ReportResult {
    Stage {
        stage: Stage,
    },
    Outcome {
        outcome: Outcome,
        checks_passed: u32,
        checks_failed: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (tempfile::TempDir, Adapter) {
        let t = tempfile::tempdir().unwrap();
        let a = Adapter::new(t.path(), Identity::new([1; 32]), "fixture").unwrap();
        (t, a)
    }
    fn hook(root: &Path, event: &str, tool: &str, session: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"hook_event_name":event,"session_id":session,"cwd":root,"tool_name":tool,"tool_use_id":"tool-1","tool_input":{"skill":"plugin:demo","args":"SECRET_PROMPT","command":"SECRET_COMMAND"},"tool_response":"SECRET_CODE","transcript_path":"/private/transcript.jsonl"})).unwrap()
    }
    #[test]
    fn launcher_runs_partition_resumed_events_but_preserve_conversation_correlation() {
        let (t, base) = setup();
        let first = Adapter::new(t.path(), Identity::new([1; 32]), "fixture")
            .unwrap()
            .with_run_id("launch-1")
            .unwrap();
        let second = Adapter::new(t.path(), Identity::new([1; 32]), "fixture")
            .unwrap()
            .with_run_id("launch-2")
            .unwrap();
        let input = hook(t.path(), "SessionEnd", "Skill", "same-conversation");
        let a = first.observe(&input, 1).unwrap().unwrap();
        let b = second.observe(&input, 2).unwrap().unwrap();
        assert_ne!(a.session_id, b.session_id);
        assert_ne!(a.event_id, b.event_id);
        assert_eq!(
            a.event_id,
            first.observe(&input, 3).unwrap().unwrap().event_id
        );
        assert_eq!(
            first
                .conversation_id(t.path().to_str().unwrap(), "same-conversation")
                .unwrap(),
            second
                .conversation_id(t.path().to_str().unwrap(), "same-conversation")
                .unwrap()
        );
        assert_ne!(
            a.session_id,
            base.observe(&input, 1).unwrap().unwrap().session_id
        );
        assert!(!serde_json::to_string(&a).unwrap().contains("launch-1"));
        assert!(base.with_run_id("bad run").is_err());
    }
    #[test]
    fn runtime_agent_ids_partition_calls_and_explicit_reports_correlate() {
        let (t, a) = setup();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&hook(t.path(), "PreToolUse", "Skill", "s")).unwrap();
        let main = a
            .observe(&serde_json::to_vec(&raw).unwrap(), 1)
            .unwrap()
            .unwrap();
        raw["agent_id"] = serde_json::json!("agent-one");
        let sub = a
            .observe(&serde_json::to_vec(&raw).unwrap(), 1)
            .unwrap()
            .unwrap();
        raw["agent_id"] = serde_json::json!("agent-two");
        let other = a
            .observe(&serde_json::to_vec(&raw).unwrap(), 1)
            .unwrap()
            .unwrap();
        assert_ne!(main.invocation_id, sub.invocation_id);
        assert_ne!(sub.invocation_id, other.invocation_id);
        let report = serde_json::json!({"session_id":"s","cwd":t.path(),"invocation_id":"tool-1","agent_id":"agent-one","report_id":"result","skill":"plugin:demo","result":{"type":"stage","stage":"finished"}});
        assert_eq!(
            sub.invocation_id,
            a.report(&serde_json::to_vec(&report).unwrap(), 2)
                .unwrap()
                .invocation_id
        );
        assert!(!serde_json::to_string(&sub).unwrap().contains("agent-one"));
        raw["agent_id"] = serde_json::json!("");
        assert!(a.observe(&serde_json::to_vec(&raw).unwrap(), 1).is_err());
    }
    #[test]
    fn projects_only_allowed_metadata() {
        let (t, a) = setup();
        let e = a
            .observe(&hook(t.path(), "PreToolUse", "Skill", "s"), 1)
            .unwrap()
            .unwrap();
        let s = serde_json::to_string(&e).unwrap();
        assert!(!s.contains("SECRET"));
        assert!(!s.contains("/private"));
        assert!(!s.contains(&t.path().to_string_lossy().to_string()));
        assert_eq!(e.skill.as_deref(), Some("plugin:demo"));
    }
    #[test]
    fn all_coding_tools_are_dropped() {
        let (t, a) = setup();
        for tool in ["Bash", "Read", "Edit", "Write", "Agent"] {
            assert!(
                a.observe(&hook(t.path(), "PostToolUse", tool, "s"), 1)
                    .unwrap()
                    .is_none()
            )
        }
    }
    #[test]
    fn success_is_loading_not_outcome() {
        let (t, a) = setup();
        assert_eq!(
            a.observe(&hook(t.path(), "PostToolUse", "Skill", "s"), 1)
                .unwrap()
                .unwrap()
                .activity,
            Activity::InstructionsLoaded
        );
    }
    #[test]
    fn concurrent_sessions_never_share_invocation() {
        let (t, a) = setup();
        let x = a
            .observe(&hook(t.path(), "PreToolUse", "Skill", "a"), 1)
            .unwrap()
            .unwrap();
        let y = a
            .observe(&hook(t.path(), "PreToolUse", "Skill", "b"), 1)
            .unwrap()
            .unwrap();
        assert_ne!(x.invocation_id, y.invocation_id);
        assert_ne!(x.event_id, y.event_id);
    }
    #[test]
    fn retries_keep_event_identity() {
        let (t, a) = setup();
        let h = hook(t.path(), "PreToolUse", "Skill", "s");
        assert_eq!(
            a.observe(&h, 1).unwrap().unwrap().event_id,
            a.observe(&h, 2).unwrap().unwrap().event_id
        );
    }
    #[test]
    fn outside_root_rejected() {
        let (_, a) = setup();
        let other = tempfile::tempdir().unwrap();
        assert!(matches!(
            a.observe(&hook(other.path(), "PreToolUse", "Skill", "s"), 1),
            Err(Error::OutsideProject)
        ));
    }
    #[test]
    fn malformed_and_oversized_rejected_without_echo() {
        let (_, a) = setup();
        assert_eq!(
            a.observe(b"SECRET bad json", 1).unwrap_err().to_string(),
            "invalid hook input"
        );
        assert!(matches!(
            bounded_input(&vec![b'x'; MAX_INPUT + 1][..]),
            Err(Error::TooLarge)
        ));
    }
    #[test]
    fn session_start_is_explicit_but_not_a_generation_claim() {
        let (t, a) = setup();
        let input = hook(t.path(), "SessionStart", "Skill", "s");
        let start = a.observe(&input, 1).unwrap().unwrap();
        assert_eq!(start.activity, Activity::SessionStarted);
        assert!(start.invocation_id.is_none());
        assert!(start.skill.is_none());
        // Hooks lack a stable lifecycle delivery ID. Repeated starts remain a single
        // observation, not invented resumptions or claimed successful skill work.
        assert_eq!(
            start.event_id,
            a.observe(&input, 3).unwrap().unwrap().event_id
        );
        let end = a
            .observe(&hook(t.path(), "SessionEnd", "Skill", "s"), 2)
            .unwrap()
            .unwrap();
        assert_ne!(start.event_id, end.event_id);
        assert!(!start.summary().contains("successful"));
    }
    #[test]
    fn end_does_not_generate_outcome() {
        let (t, a) = setup();
        let e = a
            .observe(&hook(t.path(), "SessionEnd", "Skill", "s"), 1)
            .unwrap()
            .unwrap();
        assert_eq!(e.activity, Activity::SessionEnded);
        assert!(e.skill.is_none());
        assert!(e.invocation_id.is_none());
    }
    #[test]
    fn explicit_report_is_untrusted_claim() {
        let (t, a) = setup();
        let r = serde_json::json!({"cwd":t.path(),"session_id":"s","invocation_id":"tool-1","report_id":"result-1","skill":"demo","result":{"type":"outcome","outcome":"passed","checks_passed":18,"checks_failed":0}});
        let e = a.report(&serde_json::to_vec(&r).unwrap(), 1).unwrap();
        assert_eq!(e.evidence, Evidence::Reported);
        assert!(e.summary().contains("18 checks passed"));
        let mut extra = r;
        extra["prompt"] = serde_json::json!("SECRET");
        assert!(a.report(&serde_json::to_vec(&extra).unwrap(), 1).is_err());
    }
}
