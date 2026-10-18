# Explicit lifecycle and plugin contracts

Reviewed against the official [Claude hook reference](https://code.claude.com/docs/en/hooks)
and [plugin manifest reference](https://code.claude.com/docs/en/plugins-reference) on October 18, 2026.
These are documented contracts plus fixture/binary tests, not a claim that all live client
scenarios have passed live-provider verification.

## Launcher-owned run identity

SessionStart distinguishes startup, resume, clear, compact and fork. It supplies no unique
hook-delivery identifier, so receipt time cannot establish a retry-safe generation. The
monitor never reads a transcript or assumes the last loaded skill owns subsequent coding.

A launcher that actually owns a Claude process may create a unique run ID once, put that
same value in its process-local hook configuration, and use:

```
skill-monitor hook-run STATE_DIR APPROVED_PROJECT CLAUDE_VERSION LAUNCH_ID
skill-monitor report-run STATE_DIR APPROVED_PROJECT CLAUDE_VERSION LAUNCH_ID
```

These read the same bounded hook/report JSON on stdin. The library equivalent is
`Adapter::new(...).with_run_id("launcher-owned-uuid")`. A new launch must get a new ID;
all retries and producers within that launch must reuse it. Events stay schema version 1.
The existing `session_id` becomes an installation-keyed conversation-plus-run identity,
so a resumed launch can close independently without losing its second closure to dedup.
`Adapter::conversation_id(cwd, runtime_session_id)` returns the stable keyed conversation
identity for optional local grouping, without exposing the raw runtime session ID or path.
No launch ID is stored/exported in plaintext. Existing unscoped adapters retain their prior
session identities and once-per-session lifecycle deduplication.

This is explicit caller evidence of a launch, not automatic process detection. Interactive
resume/compact cycles within one owned process still lack distinct reliable generations;
they are not invented. A user starting Claude independently has no launcher identity and
continues using ordinary `hook`. No hook writes environment variables or context back into
Claude. Hook failures remain fail-open with empty stdout.

## Subagent correlation

The hook reference documents optional `agent_id` on common hook inputs. When present on a
Skill tool event, the adapter incorporates it into the hashed invocation identity. Two
agents sharing a session/tool ID cannot collapse into one invocation. Explicit producer
reports accept optional `agent_id`; it must match the observed runtime agent to correlate.
Without it the report remains separate, never heuristically attached. Agent types, transcript
paths, messages and subagent output are discarded. The adapter does not treat SubagentStop
as proof that any skill completed. Historical IDs emitted without agent scoping are not
rewritten; they remain historical observations.

## Read-only plugin provenance

`discover_plugin(approved_root, options)` and `skill-monitor discover-plugin PLUGIN_ROOT`
read the documented `.claude-plugin/plugin.json` file. They project only plugin name,
optional version and a manifest digest, then discover the standard `skills/` and manifest
`skills` paths (a string or up to 16 directories). A root/specified directory containing
SKILL.md is supported. Manifest custom directories add to the default directory. Plugin
namespace is the manifest name; plugin version is separate from a skill's own optional
version and is never misrepresented as that skill's version.

Manifest metadata is an untrusted author claim. Discovery does not prove a plugin is enabled,
installed by a particular marketplace, signed, or effective in the current Claude settings.
Cache indexes and marketplace entry formats are not guessed. Plugins without the manifest
fail explicitly rather than guessing provenance from directory names. Only bounded manifests,
bounded skill files and selected-root-contained paths are read. Parent traversal, absolute
paths and symlink components are rejected. Commands, hooks and skill instructions are never
executed. Descriptions, repository URLs, author details and paths are never exported.

Duplicate qualified names are returned as conflicts. Duplicate paths are collapsed. Invalid
limits, unsupported manifest identity fields and unsafe paths return content-free errors.
A currently adversarially mutated tree remains outside the filesystem threat model, matching
the base registry; discovery is not an operating-system sandbox.

## Remaining gates

Implemented: explicit-launch resume partitioning, subagent invocation partitioning, producer
correlation and manifest-based plugin discovery, with offline tests. External verification:
real Claude Skill/plugin/subagent invocations once provider capacity permits, plus Windows
and Linux runtime checks. Deliberately unsupported code: guessed automatic lifecycle
boundaries, unofficial transcript recovery and marketplace-cache interpretation. Those need
stable supported signals or a separately reviewed version-specific adapter.
