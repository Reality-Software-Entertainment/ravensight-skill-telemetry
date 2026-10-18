#!/usr/bin/env python3
"""Offline end-to-end demo. Creates only a temporary project/journal; no Claude call."""
import json
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
binary = root / 'target/debug/skill-monitor'
subprocess.run(['cargo', 'build', '--offline', '-p', 'claude-adapter', '--bin', 'skill-monitor'], cwd=root, check=True)
with tempfile.TemporaryDirectory(prefix='skill-telemetry-demo-') as directory:
    project = Path(directory)
    state = project / 'journal'
    subprocess.run([str(binary), 'init', str(state)], check=True)
    def hook(session, event, tool='Skill'):
        payload = {'hook_event_name': event, 'session_id': session, 'cwd': str(project),
                   'tool_name': tool, 'tool_use_id': 'tool-1',
                   'tool_input': {'skill': 'demo:integration-check', 'args': 'PRIVATE_PROMPT', 'command': 'PRIVATE_COMMAND'},
                   'tool_response': 'PRIVATE_SOURCE'}
        subprocess.run([str(binary), 'hook', str(state), str(project), 'fixture'], input=json.dumps(payload).encode(), check=True)
    for session in ['session-a', 'session-b']:
        hook(session, 'PreToolUse')
        hook(session, 'PostToolUse')
        hook(session, 'PostToolUse', 'Bash')
    # A producer claim is explicitly separate from tool completion.
    report = {'session_id': 'session-a', 'cwd': str(project), 'invocation_id': 'tool-1',
              'report_id': 'result-1', 'skill': 'demo:integration-check',
              'result': {'type': 'outcome', 'outcome': 'passed', 'checks_passed': 18, 'checks_failed': 0}}
    subprocess.run([str(binary), 'report', str(state), str(project), 'fixture'], input=json.dumps(report).encode(), check=True)
    hook('session-b', 'SessionEnd')
    # Duplicate delivery must not create a second invocation.
    hook('session-a', 'PreToolUse')
    result = subprocess.check_output([str(binary), 'export', str(state)])
    assert b'PRIVATE_' not in result
    assert str(project).encode() not in result
    events = [json.loads(line) for line in result.splitlines()]
    assert len(events) == 6, events
    assert len({e['session_id'] for e in events}) == 2
    assert sum(e['activity']['type'] == 'outcome_reported' for e in events) == 1
    subprocess.run([str(binary), 'feed', str(state)], check=True)
    print('PASS: two sessions, coding content excluded, duplicate suppressed, one explicit outcome, one unknown outcome.')
