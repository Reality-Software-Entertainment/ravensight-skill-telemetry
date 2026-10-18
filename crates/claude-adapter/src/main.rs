use claude_adapter::{Adapter, bounded_input};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use telemetry_core::{Identity, RetrySpool, Store};

const USAGE: &str = "Skill telemetry (local-only prototype)\n  skill-monitor init STATE_DIR\n  skill-monitor hook STATE_DIR APPROVED_PROJECT CLAUDE_VERSION < hook.json\n  skill-monitor hook-run STATE_DIR APPROVED_PROJECT CLAUDE_VERSION LAUNCH_ID < hook.json\n  skill-monitor report-run STATE_DIR APPROVED_PROJECT CLAUDE_VERSION LAUNCH_ID < report.json\n  skill-monitor discover-plugin PLUGIN_ROOT\n  skill-monitor report STATE_DIR APPROVED_PROJECT CLAUDE_VERSION < report.json\n  skill-monitor feed STATE_DIR\n  skill-monitor watch STATE_DIR\n  skill-monitor export STATE_DIR\n  skill-monitor export-otlp STATE_DIR\n  skill-monitor purge STATE_DIR\n  skill-monitor discover SKILLS_ROOT [PLUGIN_NAMESPACE]\nNo settings are installed, credentials read, or network requests made.\n";
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
fn check_state(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("unsafe state directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("state directory must be private (0700)".into());
        }
    }
    Ok(())
}
fn identity(path: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    check_state(path)?;
    let key_path = path.join("identity.key");
    let meta = fs::symlink_metadata(&key_path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != 32 {
        return Err("invalid identity key file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("identity key permissions must be private".into());
        }
    }
    Ok(Identity::new(
        fs::read(key_path)?
            .try_into()
            .map_err(|_| "invalid identity key")?,
    ))
}
fn spool(path: &Path) -> Result<RetrySpool, Box<dyn std::error::Error>> {
    check_state(path)?;
    Ok(RetrySpool::open(
        &path.join("retry"),
        256,
        7 * 24 * 60 * 60 * 1000,
    )?)
}
fn store(path: &Path) -> Result<Store, Box<dyn std::error::Error>> {
    check_state(path)?;
    let mut store = Store::open(&path.join("events.sqlite"), 10_000, 7 * 24 * 60 * 60 * 1000)?;
    if spool(path)
        .and_then(|queue| Ok(queue.replay(&mut store, now())?))
        .is_err()
    {
        eprintln!("skill-monitor: retry queue unavailable; healthy journal remains usable");
    }
    Ok(store)
}
fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    if cmd == "help" || cmd == "--help" {
        print!("{USAGE}");
        return Ok(());
    }
    let path = PathBuf::from(args.get(1).ok_or("missing path")?);
    match cmd {
        "init" if args.len() == 2 => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path)?;
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).map_err(|_| "random source unavailable")?;
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(path.join("identity.key"))?;
            file.write_all(&key)?;
            file.sync_all()?;
            store(&path)?;
            println!("Initialized private local journal. No hooks installed.");
        }
        "hook" | "report" | "hook-run" | "report-run"
            if args.len()
                == if cmd == "hook-run" || cmd == "report-run" {
                    5
                } else {
                    4
                } =>
        {
            let adapter = Adapter::new(Path::new(&args[2]), identity(&path)?, &args[3])?;
            let adapter = if cmd == "hook-run" || cmd == "report-run" {
                adapter.with_run_id(&args[4])?
            } else {
                adapter
            };
            let input = bounded_input(io::stdin().lock())?;
            let ts = now();
            let event = if cmd == "hook" || cmd == "hook-run" {
                adapter.observe(&input, ts)?
            } else {
                Some(adapter.report(&input, ts)?)
            };
            if let Some(event) = event {
                match store(&path).and_then(|mut s| Ok(s.append(&event, ts)?)) {
                    Ok(_) => (),
                    Err(_) => {
                        let retry = spool(&path)?;
                        let before = retry.stats()?.dropped;
                        retry.enqueue(&event)?;
                        if retry.stats()?.dropped > before {
                            eprintln!("skill-monitor: retry queue full; event dropped");
                        } else {
                            eprintln!(
                                "skill-monitor: database unavailable; normalized event queued for retry"
                            );
                        }
                    }
                }
            }
            // No stdout in hook mode: never inject context or make permission decisions.
        }
        "feed" if args.len() == 2 => {
            let s = store(&path)?;
            for event in s.events(now())? {
                println!(
                    "{} [{}] {}",
                    event.received_ms,
                    &event.session_id[..8],
                    event.summary()
                )
            }
            eprintln!("Capacity evictions: {}", s.evicted()?);
            if let Ok(retry) = spool(&path).and_then(|queue| Ok(queue.stats()?)) {
                eprintln!(
                    "Retry queued: {}; dropped: {}; expired: {}; replayed: {}",
                    retry.queued, retry.dropped, retry.expired, retry.replayed
                );
            }
        }
        "watch" if args.len() == 2 => {
            let s = store(&path)?;
            let mut seen = std::collections::HashSet::new();
            eprintln!("Watching local skill events. Ctrl-C to stop.");
            loop {
                let events = s.events(now())?;
                let present: std::collections::HashSet<_> =
                    events.iter().map(|e| e.event_id.clone()).collect();
                seen.retain(|id| present.contains(id));
                for event in events {
                    if seen.insert(event.event_id.clone()) {
                        println!(
                            "{} [{}] {}",
                            event.received_ms,
                            &event.session_id[..8],
                            event.summary()
                        );
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        "export" if args.len() == 2 => {
            store(&path)?.export_jsonl(now(), io::stdout().lock())?;
        }
        "export-otlp" if args.len() == 2 => {
            store(&path)?.export_otlp_json(now(), io::stdout().lock())?;
        }
        "purge" if args.len() == 2 => {
            spool(&path)?.purge()?;
            store(&path)?.purge()?;
            println!("Local event history cleared.");
        }
        "discover-plugin" if args.len() == 2 => {
            let discovered = skill_registry::discover_plugin(&path, &Default::default())?;
            println!("{}", serde_json::to_string(&discovered.plugin)?);
            for skill in discovered.report.skills {
                println!("{}", serde_json::to_string(&skill.metadata)?);
            }
            eprintln!(
                "{} discovery diagnostics; {} conflicts",
                discovered.report.diagnostics.len(),
                discovered.report.conflicts.len()
            );
        }
        "discover" if (2..=3).contains(&args.len()) => {
            let mut options = skill_registry::DiscoveryOptions::default();
            if let Some(namespace) = args.get(2) {
                options.namespace = Some(namespace.clone());
                options.source = skill_registry::InstallationSource::Plugin;
            }
            let report = skill_registry::discover(&path, &options)?;
            for skill in report.skills {
                println!("{}", serde_json::to_string(&skill.metadata)?)
            }
            eprintln!(
                "{} discovery diagnostics; {} conflicts",
                report.diagnostics.len(),
                report.conflicts.len()
            );
        }
        _ => return Err("unknown command or incorrect arguments; use --help".into()),
    }
    Ok(())
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        // Hook failures are fail-open and content-free. No exit 2 (Claude blocking semantics).
        if args.first().is_some_and(|s| s == "hook" || s == "hook-run") {
            eprintln!("skill-monitor: event not recorded; inspect local setup with feed/init");
            return;
        }
        eprintln!("skill-monitor: {error}");
        std::process::exit(1)
    }
}
