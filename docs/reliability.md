# Retry and lifecycle behavior

The adapter persists only typed projected events. Raw hooks, tool arguments, responses,
transcript paths and project paths never enter the journal or retry queue.

`RetrySpool` is optional and independent of Claude. It uses a dedicated private directory,
an advisory nonblocking file lock, a bounded JSON file and atomic replacement. The CLI
allows 256 queued events; the generic API permits up to 1,024, with a 4 MiB serialized
ceiling. Queue files use private permissions. A full queue drops the new event and increments
its durable `dropped` counter. Queue contention, invalid/corrupt queue contents or filesystem
failure return an error; these cannot reliably increment durable counters, and the CLI emits
a generic content-free diagnostic. Retry errors do not disable an otherwise healthy database.
Explicit purge replaces even corrupt or oversized queue contents under the same lock without
parsing or echoing them. Hooks remain fail-open.

A subsequent CLI command opening the store replays queued events. Each successful insertion
or already-present event is removed from the queue; Store's event IDs deduplicate retries,
including a crash between database commit and queue update. Replay stops attempting database
writes after the first failure, avoiding a queue-length multiplied lock timeout. Expired
queued events are counted and discarded. `purge` clears both the queue and database. A
completely unavailable filesystem cannot be made durable by the queue.

SessionStart and SessionEnd produce explicit observed events with no skill or invocation
identity. They are deduplicated per session, not per restart. **There is no reliable generation
tracking yet:** hook deliveries do not provide a stable start/end delivery ID, and receipt
time cannot distinguish a retry from a true resumption. Consumers must not infer that a
session is currently running, that a resumed run is a fresh generation, or that session end
means its skills succeeded. Repeated session lifecycle observations can be collapsed. A
transcript watcher is deferred until its format and version compatibility are validated;
this implementation does not read transcripts.

`Store::export_otlp_json` and `skill-monitor export-otlp STATE_DIR` write an OTLP JSON logs
envelope to the provided writer/stdout. Receipt time is explicitly the event receipt time;
there are no fabricated trace/span IDs. Only normalized event metadata appears in the export.
There is no collector connection, credential handling, environment lookup or network transport.
Redirect stdout to a file explicitly if desired. Native OTLP collector ingestion is not
runtime-validated yet; the envelope is tested structurally against the expected JSON shape.

The file-lock API requires Rust 1.89 or newer; this workspace was tested with Rust 1.95.
