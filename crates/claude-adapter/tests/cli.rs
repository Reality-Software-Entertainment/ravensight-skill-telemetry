use std::{
    io::Write,
    process::{Command, Stdio},
};
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_skill-monitor")
}
fn init(path: &std::path::Path) {
    assert!(
        Command::new(binary())
            .arg("init")
            .arg(path)
            .output()
            .unwrap()
            .status
            .success()
    );
}
fn send(args: &[&str], bytes: &[u8]) -> std::process::Output {
    let mut p = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    p.stdin.take().unwrap().write_all(bytes).unwrap();
    p.wait_with_output().unwrap()
}
#[test]
fn hook_failures_are_nonblocking_and_content_free() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    init(&state);
    let out = send(
        &[
            "hook",
            state.to_str().unwrap(),
            t.path().to_str().unwrap(),
            "fixture",
        ],
        b"PRIVATE_SECRET invalid JSON",
    );
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        !String::from_utf8(out.stderr)
            .unwrap()
            .contains("PRIVATE_SECRET")
    );
}
#[test]
fn unavailable_storage_does_not_block_claude() {
    let t = tempfile::tempdir().unwrap();
    let out = send(
        &[
            "hook",
            "/not-a-real-state",
            t.path().to_str().unwrap(),
            "fixture",
        ],
        b"{}",
    );
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}
#[test]
fn observes_skill_drops_coding_and_exports_only_metadata() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    init(&state);
    let args = [
        "hook",
        state.to_str().unwrap(),
        t.path().to_str().unwrap(),
        "fixture",
    ];
    for tool in ["Skill", "Bash"] {
        let bytes=serde_json::to_vec(&serde_json::json!({"session_id":"session","cwd":t.path(),"hook_event_name":"PreToolUse","tool_name":tool,"tool_use_id":tool,"tool_input":{"skill":"example","command":"SECRET_SOURCE"},"tool_response":"SECRET_SOURCE"})).unwrap();
        let out = send(&args, &bytes);
        assert!(out.status.success());
        assert!(out.stdout.is_empty());
        assert!(out.stderr.is_empty());
    }
    let out = Command::new(binary())
        .arg("export")
        .arg(&state)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(!text.contains("SECRET_SOURCE"));
    assert!(!text.contains(t.path().to_str().unwrap()));
    assert!(text.contains("invoked"));
    assert!(
        Command::new(binary())
            .arg("purge")
            .arg(&state)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        Command::new(binary())
            .arg("export")
            .arg(&state)
            .output()
            .unwrap()
            .stdout
            .is_empty()
    );
}

#[test]
fn locked_database_queues_then_replays_without_blocking_or_leaking() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    init(&state);
    let db = rusqlite::Connection::open(state.join("events.sqlite")).unwrap();
    db.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let bytes=serde_json::to_vec(&serde_json::json!({"session_id":"s","cwd":t.path(),"hook_event_name":"PreToolUse","tool_name":"Skill","tool_use_id":"t","tool_input":{"skill":"demo","args":"SECRET"}})).unwrap();
    let started = std::time::Instant::now();
    let out = send(
        &[
            "hook",
            state.to_str().unwrap(),
            t.path().to_str().unwrap(),
            "fixture",
        ],
        &bytes,
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!String::from_utf8(out.stderr).unwrap().contains("SECRET"));
    db.execute_batch("ROLLBACK").unwrap();
    let queued = std::fs::read_to_string(state.join("retry/queue.json")).unwrap();
    assert!(queued.contains("invoked"));
    assert!(!queued.contains("SECRET"));
    assert!(!queued.contains(t.path().to_str().unwrap()));
    let out = Command::new(binary())
        .arg("export")
        .arg(&state)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 1);
    let out = Command::new(binary())
        .arg("export-otlp")
        .arg(&state)
        .output()
        .unwrap();
    assert!(out.status.success());
    let otlp: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        otlp["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let queue: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(state.join("retry/queue.json")).unwrap())
            .unwrap();
    assert_eq!(queue["events"].as_array().unwrap().len(), 0);
}

#[test]
fn corrupt_retry_queue_does_not_disable_healthy_collection_or_purge() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    init(&state);
    std::fs::write(state.join("retry/queue.json"), b"SECRET corrupt queue").unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({"session_id":"s","cwd":t.path(),"hook_event_name":"PreToolUse","tool_name":"Skill","tool_use_id":"t","tool_input":{"skill":"demo"}})).unwrap();
    let out = send(
        &[
            "hook",
            state.to_str().unwrap(),
            t.path().to_str().unwrap(),
            "fixture",
        ],
        &payload,
    );
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!String::from_utf8(out.stderr).unwrap().contains("SECRET"));
    for command in ["feed", "export"] {
        let out = Command::new(binary())
            .arg(command)
            .arg(&state)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8(out.stdout).unwrap().contains("invoked"));
        assert!(!String::from_utf8(out.stderr).unwrap().contains("SECRET"));
    }
    assert!(
        Command::new(binary())
            .arg("purge")
            .arg(&state)
            .output()
            .unwrap()
            .status
            .success()
    );
    let out = Command::new(binary())
        .arg("export")
        .arg(&state)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
}

#[test]
fn explicit_launcher_ids_keep_resume_runs_distinct_and_reports_correlated() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    init(&state);
    let payload=serde_json::to_vec(&serde_json::json!({"session_id":"same","cwd":t.path(),"hook_event_name":"PreToolUse","tool_name":"Skill","tool_use_id":"tool","tool_input":{"skill":"example"}})).unwrap();
    for run in ["launch-a", "launch-a", "launch-b"] {
        let out = send(
            &[
                "hook-run",
                state.to_str().unwrap(),
                t.path().to_str().unwrap(),
                "fixture",
                run,
            ],
            &payload,
        );
        assert!(out.status.success());
        assert!(out.stdout.is_empty());
    }
    let report=serde_json::to_vec(&serde_json::json!({"session_id":"same","cwd":t.path(),"invocation_id":"tool","skill":"example","report_id":"result","result":{"type":"stage","stage":"finished"}})).unwrap();
    assert!(
        send(
            &[
                "report-run",
                state.to_str().unwrap(),
                t.path().to_str().unwrap(),
                "fixture",
                "launch-b"
            ],
            &report
        )
        .status
        .success()
    );
    let out = Command::new(binary())
        .arg("export")
        .arg(&state)
        .output()
        .unwrap();
    let events: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.len(), 3);
    assert_ne!(events[0]["session_id"], events[1]["session_id"]);
    assert_eq!(events[1]["invocation_id"], events[2]["invocation_id"]);
    assert!(
        send(
            &[
                "hook-run",
                state.to_str().unwrap(),
                t.path().to_str().unwrap(),
                "fixture",
                "launch-b"
            ],
            b"PRIVATE bad JSON"
        )
        .status
        .success()
    );
}
