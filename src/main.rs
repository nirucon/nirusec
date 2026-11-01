mod app;
mod helper;
mod theme;

use app::View;
use nirusec::{cache, model::Status, system};

const HELP: &str = "NIRUSEC — NIRUX firewall, update and firmware GUI

Usage:
  nirusec [--open overview|firewall|ports|logs|updates|firmware|docker]
  nirusec --check [--if-stale SECONDS] [--quiet]
  nirusec --status [--json]
  nirusec --version

The checker writes a versioned cache for NIRUBAR and other suite components.
The GUI and helper never store passwords or accept arbitrary shell commands.";

fn print_status(status: &Status, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(status).unwrap_or_default()
        );
    } else {
        println!("NIRUSEC {}", env!("CARGO_PKG_VERSION"));
        println!("host: {}", status.hostname);
        println!("state: {}", status.state);
        println!("summary: {}", status.summary);
        println!("checked_at: {}", status.checked_at);
        println!("firewall: {:?}", status.firewall.enabled);
        println!("listening ports: {}", status.ports.len());
        println!(
            "updates: {} ({})",
            status.updates.count, status.updates.manager
        );
        println!(
            "firmware recommendations: {}",
            status.firmware.missing.len()
        );
        println!("docker containers: {}", status.docker.containers.len());
        for error in &status.errors {
            println!("error: {error}");
        }
    }
}

fn notify_if_needed(previous: Option<&Status>, current: &Status) {
    let was_critical = previous.is_some_and(|status| status.state == "critical");
    if current.state != "critical" || was_critical {
        return;
    }
    let _ = std::process::Command::new("notify-send")
        .args([
            "-a",
            "NIRUSEC",
            "-u",
            "critical",
            "-i",
            "security-high",
            "NIRUSEC needs attention",
            &current.summary,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| child.wait());
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--helper") {
        helper::run(&args[1..]);
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("NIRUSEC {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return;
    }
    if args.iter().any(|arg| arg == "--status") {
        let json = args.iter().any(|arg| arg == "--json");
        match cache::load() {
            Some(status) => print_status(&status, json),
            None => {
                eprintln!("nirusec: no status cache; run `nirusec --check`");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.iter().any(|arg| arg == "--check") {
        let quiet = args.iter().any(|arg| arg == "--quiet");
        let if_stale = args
            .windows(2)
            .find(|window| window[0] == "--if-stale")
            .and_then(|window| window[1].parse::<i64>().ok());
        let previous = cache::load();
        if let Some(seconds) = if_stale {
            if let Some(previous) = &previous {
                if cache::age_seconds(previous) < seconds {
                    return;
                }
            }
        }
        let Some(_lock) = cache::CheckLock::acquire() else {
            if !quiet {
                eprintln!("nirusec: another check is already running");
            }
            return;
        };
        let status = system::collect();
        if let Err(error) = cache::write(&status) {
            if !quiet {
                eprintln!("nirusec: cannot write status cache: {error}");
            }
            std::process::exit(1);
        }
        notify_if_needed(previous.as_ref(), &status);
        if !quiet {
            print_status(&status, false);
        }
        return;
    }
    let initial = args
        .windows(2)
        .find(|window| window[0] == "--open")
        .map(|window| View::parse(&window[1]));
    run_gui(initial);
}

fn run_gui(initial: Option<View>) {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NIRUSEC")
            .with_app_id("nirusec")
            .with_inner_size(egui::vec2(980.0, 720.0))
            .with_min_inner_size(egui::vec2(360.0, 320.0))
            .with_resizable(true),
        renderer: eframe::Renderer::Glow,
        vsync: true,
        multisampling: 0,
        depth_buffer: 0,
        stencil_buffer: 0,
        ..Default::default()
    };
    let result = eframe::run_native(
        "NIRUSEC",
        options,
        Box::new(move |cc| Ok(Box::new(app::NirusecApp::new(cc, initial)))),
    );
    if let Err(error) = result {
        eprintln!("nirusec: display/window initialization failed: {error}");
        eprintln!("NIRUSEC needs a graphical X11/XWayland session for the GUI. Use --check/--status headlessly.");
        std::process::exit(1);
    }
}
