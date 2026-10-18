# Claude compatibility evidence

Checked October 18, 2026 on macOS with Rust 1.95.0 and Claude Code 2.1.302.

| Capability | Evidence | Status |
| --- | --- | --- |
| Process-local command-hook configuration | Real isolated Claude session | SessionEnd delivered and persisted |
| Skill invocation and loading hooks | Official documented hooks plus fixture tests | Real invocation blocked by provider availability |
| Ordinary coding content excluded | Unit and binary integration fixtures | Passed |
| Two independent sessions and duplicate delivery | End-to-end offline demonstration | Passed |
| Explicit outcome reports | Strict producer envelope and offline demonstration | Passed; producer claims only |
| Local and plugin skill directories | Explicit-root registry fixtures | Passed; plugin namespace provided by caller |
| Concurrent/locked storage | Binary integration regression | Hook remains fail-open; bounded normalized queue replays after unlocking |
| SessionStart / resumed lifecycle | Explicit-launch and duplicate-delivery binary tests | Caller-owned launch IDs separate resumed processes; automatic interactive generation tracking remains unsupported |
| Real subagents and marketplace installation | Not exercised | Pending |
| Windows/Linux runtime behavior | Not exercised | Pending |

Live Skill invocation remains unverified due to provider availability. SessionEnd delivery was verified in an isolated fixture. No global hook settings were changed; only normalized events were retained.

Documentation references:

- [Claude hooks](https://code.claude.com/docs/en/hooks): SessionEnd and tool hook lifecycle; skill-frontmatter hooks can persist for the rest of a session, so they are not reliable skill completion boundaries.
- [Claude skills](https://code.claude.com/docs/en/skills): project/personal/plugin locations and namespaced plugin skills.
- [Claude monitoring](https://code.claude.com/docs/en/monitoring-usage): evaluate native telemetry signals before implementing an additional exporter.

Next compatibility gate: once provider access is available, repeat explicit and automatic Skill calls, plugin skill calls, resumed sessions and subagent scenarios. Capture only normalized evidence; do not persist raw hooks for debugging.

Manifest-based plugin discovery and documented subagent invocation scoping now have offline
regressions. See [supported contracts](lifecycle-and-plugin-contracts.md); no new live-provider
pass is claimed.
