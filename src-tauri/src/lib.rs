mod docker;
mod sidecar;
mod tray;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

/// Application state shared across commands
pub struct AppState {
    pub dashboard_port: u16,
    pub docker_running: std::sync::atomic::AtomicBool,
    pub scan_status: std::sync::Mutex<ScanStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Idle,
    Scanning,
    CriticalFindings,
    Error(String),
}

impl Default for ScanStatus {
    fn default() -> Self {
        ScanStatus::Idle
    }
}

/// Get the status of Docker and Temporal
#[tauri::command]
async fn get_status(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let docker_ok = state.docker_running.load(std::sync::atomic::Ordering::Relaxed);
    let scan = state.scan_status.lock().map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "docker": docker_ok,
        "scan_status": *scan,
        "dashboard_port": state.dashboard_port,
    }))
}

/// Start Docker Compose services (Temporal)
#[tauri::command]
async fn start_docker(app: tauri::AppHandle) -> Result<String, String> {
    docker::compose_up(&app).await
}

/// Stop Docker Compose services
#[tauri::command]
async fn stop_docker(app: tauri::AppHandle) -> Result<String, String> {
    docker::compose_down(&app).await
}

/// Check if Docker is available and running
#[tauri::command]
async fn check_docker() -> Result<bool, String> {
    docker::is_docker_available().await
}

/// Start a pentest scan
#[tauri::command]
async fn start_scan(
    app: tauri::AppHandle,
    url: String,
    repo: String,
    config: Option<String>,
) -> Result<String, String> {
    let state = app.state::<AppState>();
    {
        let mut status = state.scan_status.lock().map_err(|e| e.to_string())?;
        *status = ScanStatus::Scanning;
    }
    tray::update_tray_icon(&app, &ScanStatus::Scanning);

    // Start the scan via the worker sidecar
    sidecar::start_scan(&app, &url, &repo, config.as_deref()).await
}

/// Get the dashboard URL
#[tauri::command]
fn get_dashboard_url(state: tauri::State<'_, AppState>) -> String {
    format!("http://localhost:{}", state.dashboard_port)
}

pub fn run() {
    // Pick a free port for the dashboard (fallback to 4321)
    let dashboard_port = portpicker::pick_unused_port().unwrap_or(4321);

    let app_state = AppState {
        dashboard_port,
        docker_running: std::sync::atomic::AtomicBool::new(false),
        scan_status: std::sync::Mutex::new(ScanStatus::default()),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Focus the main window when a second instance is launched
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_docker,
            stop_docker,
            check_docker,
            start_scan,
            get_dashboard_url,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // Set up system tray
            tray::setup_tray(app)?;

            // Spawn async startup sequence
            tauri::async_runtime::spawn(async move {
                startup_sequence(&handle).await;
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // On close, hide to tray instead of quitting
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Donna desktop app");
}

/// Emit a startup progress event to the loading screen
fn emit_progress(app: &tauri::AppHandle, step: &str, state: &str, message: &str) {
    let _ = app.emit("startup-progress", serde_json::json!({
        "step": step,
        "state": state,
        "message": message,
    }));
}

/// Startup sequence: Docker → Temporal → Dashboard → Worker
async fn startup_sequence(app: &tauri::AppHandle) {
    log::info!("Starting Donna desktop app...");

    // Show the loading screen immediately
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }

    let state = app.state::<AppState>();

    // Step 1: Check Docker
    emit_progress(app, "docker", "active", "Checking Docker...");
    match docker::is_docker_available().await {
        Ok(true) => {
            emit_progress(app, "docker", "done", "Docker is available");
            log::info!("Docker is available");
        }
        Ok(false) | Err(_) => {
            emit_progress(app, "docker", "failed", "Docker is not running. Please start Docker.");
            log::warn!("Docker is not available — some features will be limited");
            let _ = tauri_plugin_notification::NotificationExt::notification(app)
                .builder()
                .title("Donna")
                .body("Docker is not running. Please start Docker to enable scanning.")
                .show();
            return;
        }
    }

    // Step 2: Start Docker Compose (Temporal)
    emit_progress(app, "temporal", "active", "Starting Temporal server...");
    match docker::compose_up(app).await {
        Ok(_) => {
            state.docker_running.store(true, std::sync::atomic::Ordering::Relaxed);
            log::info!("Docker Compose services started");
        }
        Err(e) => {
            emit_progress(app, "temporal", "failed", &format!("Failed to start Temporal: {}", e));
            log::error!("Failed to start Docker Compose: {}", e);
            return;
        }
    }

    // Step 3: Wait for Temporal to be healthy
    match docker::wait_for_temporal(app).await {
        Ok(_) => {
            emit_progress(app, "temporal", "done", "Temporal is healthy");
            log::info!("Temporal server is healthy");
        }
        Err(e) => {
            emit_progress(app, "temporal", "failed", &format!("Temporal health check failed: {}", e));
            log::warn!("Temporal health check failed: {}", e);
        }
    }

    // Step 4: Start dashboard sidecar
    let port = state.dashboard_port;
    emit_progress(app, "dashboard", "active", "Starting dashboard...");
    match sidecar::start_dashboard(app, port).await {
        Ok(_) => {
            emit_progress(app, "dashboard", "done", &format!("Dashboard on port {}", port));
            log::info!("Dashboard started on port {}", port);
        }
        Err(e) => {
            emit_progress(app, "dashboard", "failed", &format!("Dashboard failed: {}", e));
            log::error!("Failed to start dashboard: {}", e);
        }
    }

    // Step 5: Start worker sidecar
    emit_progress(app, "worker", "active", "Starting worker...");
    match sidecar::start_worker(app).await {
        Ok(_) => {
            emit_progress(app, "worker", "done", "Worker started");
            log::info!("Temporal worker started");
        }
        Err(e) => {
            emit_progress(app, "worker", "failed", &format!("Worker failed: {}", e));
            log::error!("Failed to start worker: {}", e);
        }
    }

    // Step 6: Wait for the dashboard to accept HTTP connections, then navigate
    let url = format!("http://localhost:{}", port);
    emit_progress(app, "worker", "done", "Waiting for dashboard to be ready...");

    let mut dashboard_ready = false;
    for attempt in 1..=30 {
        log::info!("Checking dashboard readiness (attempt {}/30)...", attempt);
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                dashboard_ready = true;
                log::info!("Dashboard is accepting connections on port {}", port);
                break;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }

    if dashboard_ready {
        // Navigate the webview directly via JS eval (more reliable than events)
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.eval(&format!("window.location.replace('{}');", url));
        }

        log::info!("Donna is ready!");
        let _ = tauri_plugin_notification::NotificationExt::notification(app)
            .builder()
            .title("Donna")
            .body("Donna is ready. Dashboard is running.")
            .show();
    } else {
        emit_progress(app, "dashboard", "failed", "Dashboard didn't start in time");
        log::error!("Dashboard failed to become ready within 30 seconds");
    }
}
