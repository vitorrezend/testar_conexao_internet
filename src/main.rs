use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Local};
use dns_lookup::lookup_host;
use reqwest::Client;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use std::time::Instant;
use tokio::time::{sleep, Duration as TokioDuration};
use std::sync::{Arc, Mutex};

// GUI and Tray imports
use eframe::egui;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, Icon, TrayIconEvent,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE, SW_SHOW, SW_RESTORE, FindWindowW, SetForegroundWindow};
use windows_sys::Win32::System::Console::GetConsoleWindow;
use ini::Ini;
use std::os::windows::ffi::OsStrExt;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AppConfig {
    target_host: String,
    auto_start: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            target_host: "www.google.com".to_string(),
            auto_start: true,
        }
    }
}

impl AppConfig {
    fn load() -> Self {
        if let Ok(conf) = Ini::load_from_file("config.ini") {
            let section = conf.section(Some("Settings"));
            let target_host = section.and_then(|s| s.get("target_host"))
                .unwrap_or("www.google.com")
                .to_string();
            let auto_start = section.and_then(|s| s.get("auto_start"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(true);
            Self { target_host, auto_start }
        } else {
            let conf = Self::default();
            conf.save();
            conf
        }
    }

    fn save(&self) {
        let mut conf = Ini::new();
        conf.with_section(Some("Settings"))
            .set("target_host", &self.target_host)
            .set("auto_start", self.auto_start.to_string());
        let _ = conf.write_to_file("config.ini");
    }
}

#[derive(Debug, Clone, PartialEq)]
struct NetworkContext {
    internal_ip: String,
    gateway: String,
    external_ip: String,
    wifi_ssid: String,
}

struct IncidentTracker {
    last_outage_start: Option<DateTime<Local>>,
    instability_count: usize,
    last_incidents: Vec<DateTime<Local>>,
    last_check: Instant,
}

struct MonitorState {
    is_running: bool,
    target_host: String,
    current_rtt: u128,
    current_ssid: String,
    current_status: String,
}

struct MonitorApp {
    state: Arc<Mutex<MonitorState>>,
    config: AppConfig,
}

impl MonitorApp {
    fn new(state: Arc<Mutex<MonitorState>>, config: AppConfig) -> Self {
        Self { state, config }
    }
}

impl eframe::App for MonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut state_lock = self.state.lock().unwrap();
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Monitor de Estabilidade de Internet");
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.label("Alvo do Teste:");
                if ui.text_edit_singleline(&mut self.config.target_host).changed() {
                    state_lock.target_host = self.config.target_host.clone();
                    self.config.save();
                }
            });

            ui.add_space(5.0);

            ui.horizontal(|ui| {
                if ui.button(if state_lock.is_running { "Parar Teste" } else { "Iniciar Teste" }).clicked() {
                    state_lock.is_running = !state_lock.is_running;
                }

                if ui.checkbox(&mut self.config.auto_start, "Iniciar automaticamente").changed() {
                    self.config.save();
                }
            });

            ui.separator();

            ui.label(format!("Status: {}", state_lock.current_status));
            ui.label(format!("Latência: {}ms", state_lock.current_rtt));
            ui.label(format!("Rede/SSID: {}", state_lock.current_ssid));
            
            ui.add_space(10.0);
            if ui.button("Fechar para a Tray").clicked() {
                set_console_visibility(false);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        });
        
        // Minimize to Tray logic
        if ctx.input(|i| i.viewport().minimized.unwrap_or(false)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false)); // Reset minimized state
        }

        // Request a redraw to keep stats updated
        ctx.request_repaint_after(TokioDuration::from_millis(500));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 0. Initial Setup
    let config = AppConfig::load();
    let state = Arc::new(Mutex::new(MonitorState {
        is_running: config.auto_start,
        target_host: config.target_host.clone(),
        current_rtt: 0,
        current_ssid: "Iniciando...".to_string(),
        current_status: "Aguardando...".to_string(),
    }));

    // Hide console by default
    set_console_visibility(false);

    // 1. Setup Tray Menu
    let tray_menu = Menu::new();
    let show_gui_item = MenuItem::new("Abrir Interface", true, None);
    let show_hide_item = MenuItem::new("Mostrar/Esconder Console", true, None);
    let open_logs_item = MenuItem::new("Abrir Pasta de Logs", true, None);
    let quit_item = MenuItem::new("Sair", true, None);

    tray_menu.append_items(&[
        &show_gui_item,
        &show_hide_item,
        &open_logs_item,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ])?;

    // 2. Initialize Tray Icon
    let icon = create_simple_icon();
    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("Monitor de Internet")
        .with_icon(icon)
        .build()?;

    // 3. Spawn Monitoring Loop
    let monitor_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = run_monitor(monitor_state).await {
            eprintln!("Monitor Erro: {}", e);
        }
    });

    // 4. GUI Event Handling (Tray Events)
    let menu_channel = MenuEvent::receiver();
    
    let gui_state = Arc::clone(&state);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 300.0])
            .with_title("Monitor de Conexão"),
        ..Default::default()
    };

    // Capture IDs as strings to be Send-safe
    let show_gui_id = show_gui_item.id().clone();
    let show_hide_id = show_hide_item.id().clone();
    let open_logs_id = open_logs_item.id().clone();
    let quit_id = quit_item.id().clone();

    // Thread to handle tray events
    let (ctx_tx, ctx_rx) = std::sync::mpsc::channel::<egui::Context>();
    let tray_channel = TrayIconEvent::receiver();

    tokio::spawn(async move {
        let mut console_visible = false;
        let mut egui_ctx: Option<egui::Context> = None;
        
        loop {
            // Try to get the context if not already present
            if egui_ctx.is_none() {
                if let Ok(ctx) = ctx_rx.try_recv() {
                    egui_ctx = Some(ctx);
                }
            }

            let mut needs_restore = false;

            // Handle Menu Events
            if let Ok(event) = menu_channel.try_recv() {
                if event.id == show_gui_id {
                    needs_restore = true;
                } else if event.id == show_hide_id {
                    console_visible = !console_visible;
                    set_console_visibility(console_visible);
                    // Also restore GUI when toggling console as requested
                    needs_restore = true;
                } else if event.id == open_logs_id {
                    let _ = Command::new("explorer").arg(".").spawn();
                } else if event.id == quit_id {
                    std::process::exit(0);
                }
            }

            // Handle Tray Icon Events (Click to restore)
            if let Ok(event) = tray_channel.try_recv() {
                match event {
                    TrayIconEvent::Click { .. } | TrayIconEvent::DoubleClick { .. } => {
                        needs_restore = true;
                    }
                    _ => {}
                }
            }

            if needs_restore {
                if let Some(ctx) = &egui_ctx {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    ctx.request_repaint();
                }
                // Native fallback for Windows 11
                force_window_restore("Monitor de Conexão");
            }

            sleep(TokioDuration::from_millis(50)).await;
        }
    });

    eframe::run_native(
        "Monitor de Conexão",
        options,
        Box::new(move |cc| {
            let _ = ctx_tx.send(cc.egui_ctx.clone());
            Ok(Box::new(MonitorApp::new(gui_state, config)))
        }),
    ).map_err(|e| anyhow!("GUI Error: {}", e))?;

    Ok(())
}

async fn run_monitor(state: Arc<Mutex<MonitorState>>) -> Result<()> {
    let client = Client::builder()
        .tcp_keepalive(Some(TokioDuration::from_secs(60)))
        .timeout(TokioDuration::from_secs(2))
        .build()?;

    let mut ctx = get_network_context(&client).await;
    let mut tracker = IncidentTracker {
        last_outage_start: None,
        instability_count: 0,
        last_incidents: Vec::new(),
        last_check: Instant::now(),
    };

    // Log Initial Context
    log_to_file("network_context.txt", &format!(
        "[{}] INÍCIO: Int:{} | GW:{} | Ext:{} | SSID:{}",
        Local::now().format("%Y-%m-%d %H:%M:%S"), ctx.internal_ip, ctx.gateway, ctx.external_ip, ctx.wifi_ssid
    ));

    // Log Session Start in Incidents
    log_to_file("incidents.txt", &format!(
        "[{}] SESSÃO INICIADA: Monitoramento ativo",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));

    loop {
        let (running, target) = {
            let s = state.lock().unwrap();
            (s.is_running, s.target_host.clone())
        };

        if !running {
            sleep(TokioDuration::from_millis(500)).await;
            continue;
        }

        let now = Local::now();
        
        // 1. Connectivity Tests
        let dns_start = Instant::now();
        let dns_res = lookup_host(&target);
        let dns_status = if dns_res.is_ok() { "OK" } else { "FAIL" };
        let dns_time = dns_start.elapsed().as_millis();

        let http_start = Instant::now();
        let url = if target.starts_with("http") { target.clone() } else { format!("https://{}", target) };
        let http_res = client.head(&url).send().await;
        
        let (http_status, http_code, http_rtt) = match http_res {
            Ok(resp) => ("OK", resp.status().as_u16().to_string(), http_start.elapsed().as_millis()),
            Err(e) => ("FAIL", format!("{:?}", e.status().map(|s| s.as_u16()).unwrap_or(0)), 0),
        };

        let ip_direct_res = client.head("http://1.1.1.1").send().await;
        let ip_direct_status = if ip_direct_res.is_ok() { "OK" } else { "FAIL" };

        let is_up = http_status == "OK";

        // Update state for GUI
        {
            let mut s = state.lock().unwrap();
            s.current_rtt = http_rtt;
            s.current_ssid = ctx.wifi_ssid.clone();
            s.current_status = if is_up { "Online".to_string() } else { "Offline".to_string() };
        }

        // 2. Network Context (Smart frequency: 30s when online, 1s when offline)
        let context_interval = if is_up { 30 } else { 1 };
        if tracker.last_check.elapsed().as_secs() >= context_interval || (is_up && tracker.last_outage_start.is_some()) {
            let new_ctx = get_network_context(&client).await;
            if new_ctx != ctx {
                log_to_file("network_context.txt", &format!(
                    "[{}] MUDANÇA: Int:{} | GW:{} | Ext:{} | SSID:{}",
                    now.format("%Y-%m-%d %H:%M:%S"), new_ctx.internal_ip, new_ctx.gateway, new_ctx.external_ip, new_ctx.wifi_ssid
                ));
                ctx = new_ctx;
            }
            tracker.last_check = Instant::now();
        }

        // 3. Incident Logic
        if !is_up {
            if tracker.last_outage_start.is_none() {
                tracker.last_outage_start = Some(now);
                tracker.instability_count += 1;
                tracker.last_incidents.push(now);
                log_to_file("incidents.txt", &format!("[{}] !!! QUEDA DETECTADA !!!", now.format("%Y-%m-%d %H:%M:%S")));
            }
        } else if let Some(start_time) = tracker.last_outage_start.take() {
            let duration = now.signed_duration_since(start_time);
            
            // Clean old incidents (older than 10 mins)
            let ten_mins_ago = now - ChronoDuration::minutes(10);
            tracker.last_incidents.retain(|&t| t > ten_mins_ago);
            let recent_flaps = tracker.last_incidents.len();

            log_to_file("incidents.txt", &format!(
                "[{}] INTERNET RESTAURADA. Duração: {}s | Instabilidade (10min): {} quedas",
                now.format("%Y-%m-%d %H:%M:%S"), duration.num_seconds(), recent_flaps
            ));
        }

        // 4. Detailed Connectivity Log
        log_to_file("connectivity.txt", &format!(
            "[{}] Alvo:{} | HTTP:{} (Code:{}, RTT:{}ms) | DNS:{} ({}ms) | IP_Direct:{}",
            now.format("%Y-%m-%d %H:%M:%S"), target, http_status, http_code, http_rtt, dns_status, dns_time, ip_direct_status
        ));

        // Console output
        if is_up {
            print!("\r[{}] Status: OK | RTT: {}ms | SSID: {}          ", now.format("%H:%M:%S"), http_rtt, ctx.wifi_ssid);
            let _ = std::io::stdout().flush();
        } else {
            println!("\n[{}] !!! SEM CONEXÃO !!! | HTTP: {} | DNS: {} | IP: {}", 
                now.format("%H:%M:%S"), http_status, dns_status, ip_direct_status);
        }

        sleep(TokioDuration::from_secs(1)).await;
    }
}

async fn get_network_context(client: &Client) -> NetworkContext {
    let internal_ip = local_ipaddress::get().unwrap_or_else(|| "Desconhecido".to_string());
    
    let gateway = get_windows_gateway().unwrap_or_else(|_| "Desconhecido".to_string());

    let external_ip = match client.get("https://api.ipify.org").send().await {
        Ok(resp) => resp.text().await.unwrap_or_else(|_| "Desconhecido".to_string()),
        Err(_) => "Fora do Ar".to_string(),
    };

    let wifi_ssid = get_windows_ssid().unwrap_or_else(|_| "N/D (Cabo?)".to_string());

    NetworkContext {
        internal_ip,
        gateway,
        external_ip,
        wifi_ssid,
    }
}

fn get_windows_gateway() -> Result<String> {
    let default_gateway = default_net::get_default_gateway().map_err(|e| anyhow!(e))?;
    Ok(default_gateway.ip_addr.to_string())
}

fn get_windows_ssid() -> Result<String> {
    let output = Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.trim().starts_with("SSID") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 {
                return Ok(parts[1].trim().to_string());
            }
        }
    }
    Err(anyhow!("SSID não encontrado"))
}

fn log_to_file(filename: &str, message: &str) {
    let now = Local::now();
    let date_folder = now.format("%Y-%m-%d").to_string();
    
    if let Err(e) = std::fs::create_dir_all(&date_folder) {
        eprintln!("Erro ao criar pasta diária {}: {}", date_folder, e);
        return;
    }

    let path = std::path::Path::new(&date_folder).join(filename);
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect(&format!("Falha ao abrir arquivo de log: {:?}", path));
    
    if let Err(e) = writeln!(file, "{}", message) {
        eprintln!("Erro ao escrever no arquivo {:?}: {}", path, e);
    }
}

fn force_window_restore(title: &str) {
    unsafe {
        let title_wide: Vec<u16> = std::ffi::OsStr::new(title)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        let hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_RESTORE);
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        }
    }
}

fn set_console_visibility(visible: bool) {
    unsafe {
        let hwnd = GetConsoleWindow();
        if !hwnd.is_null() {
            ShowWindow(hwnd, if visible { SW_SHOW } else { SW_HIDE });
        }
    }
}

fn create_simple_icon() -> Icon {
    let width = 32;
    let height = 32;
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        for x in 0..width {
            let dist = (((x as i32 - 16).pow(2) + (y as i32 - 16).pow(2)) as f32).sqrt();
            if dist < 12.0 {
                rgba.extend_from_slice(&[0, 180, 0, 255]); // Green dot
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]); // Transparent
            }
        }
    }
    Icon::from_rgba(rgba, width, height).expect("Falha ao criar ícone")
}
