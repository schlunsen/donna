use tauri::AppHandle;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandEvent;

/// Start the Astro SSR dashboard as a sidecar process
pub async fn start_dashboard(app: &AppHandle, port: u16) -> Result<(), String> {
    let shell = app.shell();

    let sidecar = shell
        .sidecar("donna-dashboard")
        .map_err(|e| format!("Failed to create dashboard sidecar: {}", e))?
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1".to_string());

    let (mut rx, _child) = sidecar
        .spawn()
        .map_err(|e| format!("Failed to spawn dashboard sidecar: {}", e))?;

    // Monitor sidecar output in background
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    let line_str = String::from_utf8_lossy(&line);
                    log::info!("[dashboard] {}", line_str);
                }
                CommandEvent::Stderr(line) => {
                    let line_str = String::from_utf8_lossy(&line);
                    log::warn!("[dashboard] {}", line_str);
                }
                CommandEvent::Terminated(payload) => {
                    log::error!(
                        "[dashboard] Process terminated with code: {:?}, signal: {:?}",
                        payload.code,
                        payload.signal
                    );
                    let _ = tauri_plugin_notification::NotificationExt::notification(&app_handle)
                        .builder()
                        .title("Donna")
                        .body("Dashboard process crashed. Restart Donna to recover.")
                        .show();
                    break;
                }
                _ => {}
            }
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
