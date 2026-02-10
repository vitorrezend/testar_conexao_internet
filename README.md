# Internet Stability Monitor (Rust)

A lightweight Rust application to monitor network stability by pinging multiple endpoints, tracking latency, DNS resolution, and network context (IP/SSID).

## Features
- **Daily Log Organization**: Logs are automatically organized into folders by date (e.g., `2026-02-10/`).
- **Granular Diagnostics**:
    - `connectivity.txt`: HTTP RTT, DNS resolution time, and direct IP connectivity.
    - `network_context.txt`: Internal IP, Gateway, External IP, and Wi-Fi SSID.
    - `incidents.txt`: Dedicated log for outages and recovery with duration tracking.
- **Stealth Mode**: Starts hidden in the system tray (notification area).
- **System Tray Integration**:
    - Toggle console visibility.
    - Quick access to log folders.
    - Persistent monitoring in the background.

## How to Run
1. Ensure you have Rust installed.
2. Clone the repository.
3. Run with:
   ```bash
   cargo run
   ```
4. For the optimized production version:
   ```bash
   cargo build --release
   ```
   The executable will be in `target/release/testar_internet.exe`.

## Dependencies
- `tokio`: Async runtime.
- `reqwest`: HTTP client for tests and external IP discovery.
- `tray-icon` & `tao`: System tray and event loop management.
- `windows-sys`: Windows API for window management.
- `chrono`: Daily rotation and timestamping.
