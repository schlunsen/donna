use tauri::{AppHandle, Manager};
use tokio::process::Command;

/// Path resolution for Docker on macOS GUI apps.
/// GUI apps don't inherit the shell PATH, so Docker may not be found.
fn docker_path() -> String {
    // Try common Docker locations on macOS
    let candidates = [
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/usr/bin/docker",
        "docker", // fallback to PATH
    ];

    for candidate in &candidates {
        if std::path::Path::new(candidate).exists() || *candidate == "docker" {
            return candidate.to_string();
        }
    }

    "docker".to_string()
}

/// Resolve the docker-compose.tauri.yml path relative to the app's resource dir
fn compose_file_path(app: &AppHandle) -> Result<String, String> {
    // In development, use the project-local compose file
    // In production, it's bundled as a resource
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|e| format!("Failed to get resource dir: {}", e))?;

    // Use the Tauri-specific compose file (only Temporal, no dashboard/worker containers)
    let compose_path = resource_dir.join("docker-compose.tauri.yml");

    if compose_path.exists() {
        Ok(compose_path.to_string_lossy().to_string())
    } else {
        // Fallback: try src-tauri/ directory (development mode)
        let dev_path = "src-tauri/docker-compose.tauri.yml";
        if std::path::Path::new(dev_path).exists() {
            return Ok(dev_path.to_string());
        }
        // Last resort: use the root docker-compose.yml
        Ok("docker-compose.yml".to_string())
    }
}

/// Check if Docker daemon is available
pub async fn is_docker_available() -> Result<bool, String> {
    let docker = docker_path();

    let output = Command::new(&docker)
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .await
        .map_err(|e| format!("Failed to run docker: {}", e))?;

    Ok(output.status.success())
}

/// Check if Temporal is already reachable on port 7233 (from any source)
async fn is_temporal_port_open() -> bool {
    tokio::net::TcpStream::connect("127.0.0.1:7233").await.is_ok()
}

/// Start Docker Compose services (Temporal server)
pub async fn compose_up(app: &AppHandle) -> Result<String, String> {
    // If Temporal is already running (e.g., from a separate docker compose), skip startup
    if is_temporal_port_open().await {
        log::info!("Temporal is already running on port 7233 — skipping compose up");
        return Ok("Temporal already running".to_string());
    }

    let docker = docker_path();
    let compose_file = compose_file_path(app)?;

    log::info!("Starting Docker Compose with file: {}", compose_file);

    let output = Command::new(&docker)
        .args([
            "compose",
            "-f",
            &compose_file,
            "up",
            "-d",
            "temporal", // Only start Temporal — dashboard and worker run as sidecars
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to run docker compose up: {}", e))?;

    if output.status.success() {
        Ok("Docker Compose started".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If port is already in use, Temporal is likely running from another source
        if stderr.contains("port is already allocated") || stderr.contains("address already in use") {
            log::info!("Port 7233 already in use — assuming Temporal is running");
            return Ok("Temporal already running (external)".to_string());
        }
        Err(format!("Docker Compose failed: {}", stderr))
    }
}

/// Stop Docker Compose services
pub async fn compose_down(app: &AppHandle) -> Result<String, String> {
    let docker = docker_path();
    let compose_file = compose_file_path(app)?;

    let output = Command::new(&docker)
        .args(["compose", "-f", &compose_file, "down"])
        .output()
        .await
        .map_err(|e| format!("Failed to run docker compose down: {}", e))?;

    if output.status.success() {
        Ok("Docker Compose stopped".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Docker Compose down failed: {}", stderr))
    }
}

/// Wait for Temporal server to become healthy (up to 60 seconds)
pub async fn wait_for_temporal(app: &AppHandle) -> Result<(), String> {
    let docker = docker_path();
    let compose_file = compose_file_path(app)?;

    for attempt in 1..=12 {
        log::info!(
            "Waiting for Temporal to be healthy (attempt {}/12)...",
            attempt
        );

        let output = Command::new(&docker)
            .args([
                "compose",
                "-f",
                &compose_file,
                "exec",
                "temporal",
                "temporal",
                "operator",
                "cluster",
                "health",
                "--address",
                "localhost:7233",
            ])
            .output()
            .await
            .map_err(|e| format!("Health check command failed: {}", e))?;

        if output.status.success() {
            return Ok(());
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    Err("Temporal did not become healthy within 60 seconds".to_string())
}
