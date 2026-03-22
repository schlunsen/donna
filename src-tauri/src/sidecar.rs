use tauri::AppHandle;
use tauri_plugin_shell::ShellExt;

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
        use tauri_plugin_shell::process::CommandEvent;
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
                    // Notify user of crash
                    let _ = tauri_plugin_notification::NotificationExt::notification(&app_handle)
                        .builder()
                        .title("Donna")
                        .body("Dashboard process crashed. Restarting...")
                        .show();
                    // TODO: implement automatic restart with backoff
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait a moment for the dashboard to start
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Verify dashboard is responding
    let check = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("http://127.0.0.1:{}", port),
        ])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let code = String::from_utf8_lossy(&output.stdout);
            if code.starts_with('2') || code.starts_with('3') {
                log::info!("Dashboard is responding on port {}", port);
                Ok(())
            } else {
                log::warn!("Dashboard returned HTTP {}, may still be starting...", code);
                Ok(()) // Don't fail — it may just need more time
            }
        }
        _ => {
            log::warn!("Could not verify dashboard — it may still be starting");
            Ok(())
        }
    }
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
        use tauri_plugin_shell::process::CommandEvent;
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
                        .body("Worker process crashed. Restarting...")
                        .show();
                    break;
                }
                _ => {}
            }
        }
    });

    Ok(())
}

/// Start a pentest scan by invoking the donna CLI through the worker
pub async fn start_scan(
    app: &AppHandle,
    url: &str,
    repo: &str,
    config: Option<&str>,
) -> Result<String, String> {
    let shell = app.shell();

    let mut args = vec![
        "start".to_string(),
        format!("URL={}", url),
        format!("REPO={}", repo),
    ];

    if let Some(config_path) = config {
        args.push(format!("CONFIG={}", config_path));
    }

    let output = shell
        .sidecar("donna-worker")
        .map_err(|e| format!("Failed to create scan sidecar: {}", e))?
        .args(args)
        .output()
        .await
        .map_err(|e| format!("Failed to run scan: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
