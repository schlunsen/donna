mod docker;
mod sidecar;
mod tray;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, Url};

/// Application state shared across commands
pub struct AppState {
    pub dashboard_port: u16,
    pub docker_running: std::sync::atomic::AtomicBool,
    pub scan_status: std::sync::Mutex<ScanStatus>,
    pub tauri_auth_token: std::sync::Mutex<Option<String>>,
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
    // Initialize logging — writes to stderr (visible when launched from terminal)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    log::info!("Donna desktop app starting...");

    // Pick a free port for the dashboard (fallback to 4321)
    let dashboard_port = portpicker::pick_unused_port().unwrap_or(4321);
    log::info!("Dashboard will use port {}", dashboard_port);

    let app_state = AppState {
        dashboard_port,
        docker_running: std::sync::atomic::AtomicBool::new(false),
        scan_status: std::sync::Mutex::new(ScanStatus::default()),
        tauri_auth_token: std::sync::Mutex::new(None),
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

/// Kill any lingering dashboard node processes from previous runs
fn cleanup_stale_processes() {
    // Use pkill to terminate any existing "node ... entry.mjs" processes
    let _ = std::process::Command::new("pkill")
        .args(["-f", "entry.mjs"])
        .output();
    // Brief pause to let processes exit
    std::thread::sleep(std::time::Duration::from_millis(500));
    log::info!("Cleaned up stale dashboard processes (if any)");
}

/// Startup sequence: Docker → Temporal → Dashboard → Worker
async fn startup_sequence(app: &tauri::AppHandle) {
    log::info!("Starting Donna desktop app...");

    // Clean up any stale dashboard processes from previous runs
    cleanup_stale_processes();

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
    let tauri_auth_token = match sidecar::start_dashboard(app, port).await {
        Ok(token) => {
            emit_progress(app, "dashboard", "done", &format!("Dashboard on port {}", port));
            log::info!("Dashboard started on port {}", port);
            // Store token in app state for potential re-login
            if let Ok(mut stored_token) = state.tauri_auth_token.lock() {
                *stored_token = Some(token.clone());
            }
            Some(token)
        }
        Err(e) => {
            emit_progress(app, "dashboard", "failed", &format!("Dashboard failed: {}", e));
            log::error!("Failed to start dashboard: {}", e);
            None
        }
    };

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

    // Step 6: Navigate WebView to the dashboard with auto-login
    // start_dashboard() already waited for the port to be ready
    if let Some(token) = tauri_auth_token {
        // Navigate to the auto-login endpoint — it will set session cookies and redirect to /
        let login_url = format!(
            "http://localhost:{}/api/auth/tauri-login?token={}",
            port, token
        );

        // Small extra delay to ensure the HTTP server is fully initialized
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Verify the dashboard is reachable before navigating
        let dashboard_ready = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok();

        if dashboard_ready {
            log::info!("Dashboard reachable on port {}, navigating to auto-login...", port);
            if let Some(window) = app.get_webview_window("main") {
                match Url::parse(&login_url) {
                    Ok(parsed_url) => {
                        log::info!("Navigating WebView to auto-login endpoint");
                        match window.navigate(parsed_url) {
                            Ok(_) => log::info!("WebView navigation initiated successfully"),
                            Err(e) => {
                                log::error!("WebView navigate() failed: {} — trying eval fallback", e);
                                let _ = window.eval(&format!("window.location.replace('{}');", login_url));
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to parse login URL: {}", e);
                    }
                }
            } else {
                log::error!("Could not find main window for navigation!");
            }

            log::info!("Donna is ready!");
            let _ = tauri_plugin_notification::NotificationExt::notification(app)
                .builder()
                .title("Donna")
                .body("Donna is ready. Dashboard is running.")
                .show();
        } else {
            emit_progress(app, "dashboard", "failed", "Dashboard is not reachable");
            log::error!("Dashboard not reachable on port {} after startup", port);
        }
    }
}
