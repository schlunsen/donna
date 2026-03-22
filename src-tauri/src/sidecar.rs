use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandEvent;
use tokio::process::Command as TokioCommand;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Generate a random hex string for auth secrets
fn generate_secret() -> String {
    use std::fmt::Write;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap_or_default();
    let mut hex = String::with_capacity(64);
    for b in &bytes {
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Find the Node.js binary (macOS GUI apps don't inherit shell PATH)
fn find_node() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());

    log::info!("Finding node, HOME={}", home);

    // Check NVM versions (pick the latest/highest version)
    let nvm_dir = format!("{}/.nvm/versions/node", home);
    if let Ok(entries) = std::fs::read_dir(&nvm_dir) {
        let mut versions: Vec<_> = entries
            .flatten()
            .filter(|e| e.path().join("bin/node").exists())
            .collect();
        // Sort to pick the latest version
        versions.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
        if let Some(entry) = versions.first() {
            let node_path = entry.path().join("bin/node");
            log::info!("Found node via NVM: {}", node_path.display());
            return node_path.to_string_lossy().to_string();
        }
    }

    // Check common locations
    for candidate in &[
        "/opt/homebrew/bin/node",
        "/usr/local/bin/node",
        "/usr/bin/node",
    ] {
        if std::path::Path::new(candidate).exists() {
            log::info!("Found node at: {}", candidate);
            return candidate.to_string();
        }
    }

    // Try to find via login shell
    if let Ok(output) = std::process::Command::new("/bin/bash")
        .args(["-lc", "which node"])
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                log::info!("Found node via bash -lc: {}", path);
                return path;
            }
        }
    }

    log::warn!("Could not find node, falling back to 'node'");
    "node".to_string()
}

/// Find the dashboard directory (needs both dist/ and node_modules/)
fn find_dashboard_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    // Try relative to exe (for Tauri bundle: Contents/MacOS/../Resources/)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // Check if dashboard/ is next to the project
            let project_root = exe_dir.join("../../../../..");
            let dashboard = project_root.join("dashboard");
            if dashboard.join("dist/server/entry.mjs").exists() {
                log::info!("Found dashboard via exe relative path: {}", dashboard.display());
                return Ok(dashboard);
            }
        }
    }

    // Development fallback: CWD/dashboard/
    let dev_path = std::path::PathBuf::from("dashboard");
    if dev_path.join("dist/server/entry.mjs").exists() {
        log::info!("Found dashboard at CWD/dashboard/");
        return Ok(dev_path);
    }

    // Also check in common project locations
    let home = std::env::var("HOME").unwrap_or_default();
    for candidate in &[
        format!("{}/projects/donna/dashboard", home),
        format!("{}/donna/dashboard", home),
    ] {
        let path = std::path::PathBuf::from(candidate);
        if path.join("dist/server/entry.mjs").exists() {
            log::info!("Found dashboard at: {}", path.display());
            return Ok(path);
        }
    }

    Err("Dashboard directory not found. Run 'cd dashboard && npm run build' first.".to_string())
}

/// Start the Astro SSR dashboard as a child process (not Tauri sidecar)
pub async fn start_dashboard(app: &AppHandle, port: u16) -> Result<(), String> {
    let node = find_node();
    let dashboard_dir = find_dashboard_dir(app)?;
    // Canonicalize to get an absolute path, avoiding doubling
    let dashboard_dir = dashboard_dir.canonicalize()
        .map_err(|e| format!("Failed to resolve dashboard dir: {}", e))?;
    let entry = dashboard_dir.join("dist/server/entry.mjs");

    log::info!("Starting dashboard with node={}, entry={}", node, entry.display());

    let auth_secret = generate_secret();

    let mut child = TokioCommand::new(&node)
        .arg(&entry)
        .current_dir(&dashboard_dir)
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1")
        .env("BETTER_AUTH_SECRET", auth_secret)
        .env("AUTH_BASE_URL", format!("http://localhost:{}", port))
        .env("AUTH_TRUSTED_ORIGINS", format!("http://localhost:{}", port))
        .env("TEMPORAL_ADDRESS", "localhost:7233")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn dashboard: {} (node={})", e, node))?;

    // Monitor stdout in background
    if let Some(stdout) = child.stdout.take() {
        tauri::async_runtime::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log::info!("[dashboard] {}", line);
            }
        });
    }

    // Monitor stderr in background
    let app_handle = app.clone();
    if let Some(stderr) = child.stderr.take() {
        tauri::async_runtime::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log::warn!("[dashboard] {}", line);
            }
        });
    }

    // Monitor process exit in background
    let app_handle2 = app.clone();
    tauri::async_runtime::spawn(async move {
        match child.wait().await {
            Ok(status) => {
                if !status.success() {
                    log::error!("[dashboard] Process exited with status: {}", status);
                    let _ = tauri_plugin_notification::NotificationExt::notification(&app_handle2)
                        .builder()
                        .title("Donna")
                        .body("Dashboard process crashed. Restart Donna to recover.")
                        .show();
                }
            }
            Err(e) => log::error!("[dashboard] Wait error: {}", e),
        }
    });

    // Wait for the dashboard to start accepting connections
    wait_for_port(port, 15).await?;

    Ok(())
}

/// Start the Temporal worker as a sidecar process
pub async fn start_worker(app: &AppHandle) -> Result<(), String> {
    let shell = app.shell();

    let sidecar = shell
        .sidecar("donna-worker")
        .map_err(|e| format!("Failed to create worker sidecar: {}", e))?
        .env("TEMPORAL_ADDRESS", "localhost:7233".to_string());

    let (mut rx, _child) = sidecar
        .spawn()
        .map_err(|e| format!("Failed to spawn worker sidecar: {}", e))?;

    // Monitor worker output in background
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    let line_str = String::from_utf8_lossy(&line);
                    log::info!("[worker] {}", line_str);

                    // Detect scan completion from worker output
                    if line_str.contains("workflow completed") {
                        let state = app_handle.state::<crate::AppState>();
                        if let Ok(mut status) = state.scan_status.lock() {
                            *status = crate::ScanStatus::Idle;
                        }
                        crate::tray::update_tray_icon(&app_handle, &crate::ScanStatus::Idle);

                        let _ = tauri_plugin_notification::NotificationExt::notification(
                            &app_handle,
                        )
                        .builder()
                        .title("Donna — Scan Complete")
                        .body("Pentest scan has finished. Check the dashboard for results.")
                        .show();
                    }

                    // Detect critical findings
                    if line_str.contains("CRITICAL") || line_str.contains("severity: critical") {
                        let state = app_handle.state::<crate::AppState>();
                        if let Ok(mut status) = state.scan_status.lock() {
                            *status = crate::ScanStatus::CriticalFindings;
                        }
                        crate::tray::update_tray_icon(
                            &app_handle,
                            &crate::ScanStatus::CriticalFindings,
                        );

                        let _ = tauri_plugin_notification::NotificationExt::notification(
                            &app_handle,
                        )
                        .builder()
                        .title("Donna — Critical Finding!")
                        .body("A critical vulnerability has been discovered.")
                        .show();
                    }
                }
                CommandEvent::Stderr(line) => {
                    let line_str = String::from_utf8_lossy(&line);
                    log::warn!("[worker] {}", line_str);
                }
                CommandEvent::Terminated(payload) => {
                    log::error!(
                        "[worker] Process terminated with code: {:?}, signal: {:?}",
                        payload.code,
                        payload.signal
                    );
                    let _ = tauri_plugin_notification::NotificationExt::notification(&app_handle)
                        .builder()
                        .title("Donna")
                        .body("Worker process crashed. Restart Donna to recover.")
                        .show();
                    break;
                }
                _ => {}
            }
        }
    });

    Ok(())
}

/// Start a pentest scan via the Temporal client.
///
/// Scans are initiated by signaling the Temporal server (which the already-running
/// worker picks up), NOT by spawning a new worker process.
pub async fn start_scan(
    app: &AppHandle,
    url: &str,
    repo: &str,
    config: Option<&str>,
) -> Result<String, String> {
    let shell = app.shell();

    // Use the Temporal client entry point (client.js), not the worker
    // The client connects to Temporal and starts a workflow that the worker executes
    let mut args = vec![
        "dist/temporal/client.js".to_string(),
        url.to_string(),
        repo.to_string(),
    ];

    if let Some(config_path) = config {
        args.push(format!("--config={}", config_path));
    }

    // Run via node (or a bundled client sidecar in the future)
    let output = shell
        .command("node")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("Failed to start scan: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Wait for a TCP port to become reachable (cross-platform, no curl dependency)
async fn wait_for_port(port: u16, timeout_secs: u64) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    while tokio::time::Instant::now() < deadline {
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                log::info!("Port {} is accepting connections", port);
                return Ok(());
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }

    log::warn!("Port {} did not become available within {}s — continuing anyway", port, timeout_secs);
    Ok(()) // Don't fail — the sidecar may just need more time
}
