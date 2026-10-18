# Ravensight Skill Telemetry

Independent, local-only Rust foundation for a skill activity monitor. This is a pre-release source workspace with three crates: telemetry-core, claude-adapter and skill-registry. It has no Ravensight API/account dependency and makes no network requests.

## Run the demonstration

Requires Rust 1.95 and Python 3. Cargo dependencies must already be cached for offline commands; use `cargo fetch --locked` explicitly if needed.

```sh
cargo test --workspace --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
python3 examples/demo.py
```

The demo uses a temporary project and journal. It feeds synthetic hooks from two sessions, excludes command/prompt/source content, deduplicates an invocation and shows a reported result separately from an unknown outcome. It does not call Claude.

## Local command line

```sh
cargo build --offline -p claude-adapter --bin skill-monitor
./target/debug/skill-monitor init /absolute/path/to/new-private-state
./target/debug/skill-monitor discover /approved/project/.claude/skills
./target/debug/skill-monitor discover /approved/plugin/skills plugin-name
./target/debug/skill-monitor watch /absolute/path/to/new-private-state
```

`init` requires a new state directory with an existing parent. It creates a random installation key and SQLite journal with private Unix permissions. `watch` reads the local journal every 250 ms; it is not a transcript watcher. Ctrl-C stops the watch. `feed` prints current history, `export` writes normalized JSONL and `export-otlp` writes an OTLP JSON log envelope to stdout and `purge` deletes history and queued retries while preserving the identity key.

Hook invocation:

```sh
./target/debug/skill-monitor hook STATE_DIR APPROVED_PROJECT CLAUDE_VERSION
```

Supply Claude's hook JSON on stdin. Only Skill tool invocations, Skill tool loading/failure and session start/closure are retained. Skill arguments and tool responses are ignored. The current working directory must resolve within the approved project. Input is capped at 256 KiB. Hook mode returns no stdout, never makes permission decisions and exits successfully even when collection fails. Its generic stderr warning contains no raw input. Database failures queue normalized events in a bounded retry spool. Queue overflow, contention or unavailable storage can still lose events, with content-free diagnostics; see [reliability details](docs/reliability.md).

This program does not install hooks. For an explicitly configured test session, use the official Claude command-hook configuration with `PreToolUse`, `PostToolUse`, `PostToolUseFailure` filtered to `Skill`, and `SessionStart`/`SessionEnd`. Point each at the command above with appropriately quoted absolute paths. Pass configuration only to that test session. Do not overwrite global settings. See [compatibility evidence](docs/COMPATIBILITY.md).

## Explicit outcome reports

`report STATE_DIR APPROVED_PROJECT CLAUDE_VERSION` reads a strict JSON envelope:

```json
{
  "session_id": "session-a",
  "cwd": "/approved/project",
  "invocation_id": "tool-1",
  "report_id": "result-1",
  "skill": "demo:integration-check",
  "result": {
    "type": "outcome",
    "outcome": "passed",
    "checks_passed": 18,
    "checks_failed": 0
  }
}
```

The invocation ID must be the matching tool-use ID for correlation; the prototype does not invent or automatically supply it to skills. Independent producer invocations may use their own IDs and remain separate. A repeated report ID is first-write-wins, not an update. Producers must use a new report ID for a new result. A stage result instead uses `{"type":"stage","stage":"checking"}` with started/checking/finished supported. These are explicitly **reported claims**, not independently verified attestations. No prose summary or raw output field is accepted.

## Evidence and privacy

“Instructions loaded” never means “task completed.” Session closure leaves unreported outcomes unknown. Skill names and namespace/version metadata are visible; do not put secrets in identifiers. Session/project/invocation IDs are domain-separated HMACs using a local installation key. Absolute paths remain local. The journal is not encrypted at rest; private file permissions are not encryption.

Default history is seven days and 10,000 events, with a SQLite page limit of about 128 MiB. Read and append operations delete expired records; no background cleanup runs while the program is stopped. Capacity eviction prefers keeping outcome/failure/closure events and exposes an eviction counter. Deletion cannot guarantee erasure from backups or underlying storage snapshots. Export is explicit and local stdout only.

## Implementation boundaries

- Registry discovery is read-only, one level deep, bounded, and skips symlinks. Caller supplies source and plugin namespace; installation provenance/version is not inferred. Only a documented simple frontmatter scalar subset is supported.
- Approved directories must not be concurrently modified by an adversary. This prototype does not provide descriptor-relative traversal or an adversarial local-user sandbox.
- Session closure is deduplicated once per session; repeated resume/close cycles are not yet a lifecycle timeline.
- No transcript watcher, hook installer, OTLP transport, desktop GUI, cloud integration, remote-session collection, marketplace client or publication.
- Full live Skill-tool behavior remains unverified due to provider availability. The real SessionEnd hook was received successfully. Fixture tests are not a replacement for that remaining gate.

The three components are licensed under Apache-2.0; see LICENSE and NOTICE. Package releases remain held. Cargo packages have `publish = false`. Existing Ravensight skills and SDK licenses are unchanged.

## Explicit launch correlation and plugin manifests

A caller-owned launch ID can distinguish resumed Claude processes without changing the
export schema; documented agent IDs partition subagent skill invocations. `discover-plugin`
reads manifest identity and skill paths from an explicitly selected plugin directory. See
[lifecycle and plugin contracts](docs/lifecycle-and-plugin-contracts.md) for library APIs,
CLI usage, privacy limits and the remaining real-client verification gates.
