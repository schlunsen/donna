mod docker;
mod sidecar;
mod tray;

use serde::{Deserialize, Serialize};
use tauri::Manager;

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

/// Startup sequence: Docker → Temporal → Dashboard → Worker
async fn startup_sequence(app: &tauri::AppHandle) {
    log::info!("Starting Donna desktop app...");

    let state = app.state::<AppState>();

    // Step 1: Check Docker
    match docker::is_docker_available().await {
        Ok(true) => {
            log::info!("Docker is available");
        }
        Ok(false) | Err(_) => {
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
    match docker::compose_up(app).await {
        Ok(_) => {
            state.docker_running.store(true, std::sync::atomic::Ordering::Relaxed);
            log::info!("Docker Compose services started");
        }
        Err(e) => {
            log::error!("Failed to start Docker Compose: {}", e);
            return;
        }
    }

    // Step 3: Wait for Temporal to be healthy
    match docker::wait_for_temporal(app).await {
        Ok(_) => log::info!("Temporal server is healthy"),
        Err(e) => log::warn!("Temporal health check failed: {}", e),
    }

    // Step 4: Start dashboard sidecar
    let port = state.dashboard_port;
    match sidecar::start_dashboard(app, port).await {
        Ok(_) => log::info!("Dashboard started on port {}", port),
        Err(e) => log::error!("Failed to start dashboard: {}", e),
    }

    // Step 5: Start worker sidecar
    match sidecar::start_worker(app).await {
        Ok(_) => log::info!("Temporal worker started"),
        Err(e) => log::error!("Failed to start worker: {}", e),
    }

    // Step 6: Show the main window pointing at the dashboard
    if let Some(window) = app.get_webview_window("main") {
        let url = format!("http://localhost:{}", port);
        let _ = window.navigate(url.parse().unwrap());
        let _ = window.show();
        let _ = window.set_focus();
    }

    log::info!("Donna is ready!");
    let _ = tauri_plugin_notification::NotificationExt::notification(app)
        .builder()
        .title("Donna")
        .body("Donna is ready. Dashboard is running.")
        .show();
}
