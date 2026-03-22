use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    AppHandle, Manager, Url,
};

use crate::ScanStatus;

/// Set up the system tray with menu items
pub fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItem::with_id(app, "show", "Show Dashboard", true, None::<&str>)?;
    let start_scan = MenuItem::with_id(app, "start_scan", "Start Scan...", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let status = MenuItem::with_id(app, "status", "Status: Idle", false, None::<&str>)?;
    let separator2 = PredefinedMenuItem::separator(app)?;
    let stop_docker = MenuItem::with_id(app, "stop_docker", "Stop Services", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Donna", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &show,
            &start_scan,
            &separator,
            &status,
            &separator2,
            &stop_docker,
            &quit,
        ],
    )?;

    TrayIconBuilder::with_id("donna-tray")
        .menu(&menu)
        .tooltip("Donna — AI Pentesting")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "start_scan" => {
                // Open the dashboard's scan page
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                    // Navigate to the scan start page
                    let state = app.state::<crate::AppState>();
                    let url = format!("http://localhost:{}/scan/new", state.dashboard_port);
                    if let Ok(parsed) = Url::parse(&url) {
                        let _ = window.navigate(parsed);
                    }
                }
            }
            "stop_docker" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    match crate::docker::compose_down(&handle).await {
                        Ok(_) => log::info!("Docker services stopped"),
                        Err(e) => log::error!("Failed to stop Docker: {}", e),
                    }
                });
            }
            "quit" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    // Gracefully stop Docker before quitting
                    let _ = crate::docker::compose_down(&handle).await;
                    handle.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

/// Update the tray icon and tooltip based on scan status
pub fn update_tray_icon(app: &AppHandle, status: &ScanStatus) {
    if let Some(tray) = app.tray_by_id("donna-tray") {
        let tooltip = match status {
            ScanStatus::Idle => "Donna — Idle",
            ScanStatus::Scanning => "Donna — Scanning...",
            ScanStatus::CriticalFindings => "Donna — Critical Findings!",
            ScanStatus::Error(msg) => {
                log::error!("Tray error status: {}", msg);
                "Donna — Error"
            }
        };
        let _ = tray.set_tooltip(Some(tooltip));

        // Update tray icon based on status
        // In production, we'd use different colored icons
        // For now, use the same icon but change tooltip
        let icon_path = match status {
            ScanStatus::Idle => "icons/tray-idle.png",
            ScanStatus::Scanning => "icons/tray-scanning.png",
            ScanStatus::CriticalFindings => "icons/tray-critical.png",
            ScanStatus::Error(_) => "icons/tray-error.png",
        };

        // Try to load the status-specific icon, fall back to default
        if let Ok(icon) = Image::from_path(icon_path) {
            let _ = tray.set_icon(Some(icon));
        }
    }
}
