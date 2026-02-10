use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Local, Timelike};
use dns_lookup::lookup_host;
use reqwest::Client;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use std::time::Instant;
use tokio::time::{sleep, Duration as TokioDuration};

// Tray and UI imports
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, Icon,
};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE, SW_SHOW};
use windows_sys::Win32::System::Console::GetConsoleWindow;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    // 0. Hide console immediately for stealth startup
    set_console_visibility(false);

    // 1. Setup Tray Menu
    let tray_menu = Menu::new();
    let show_hide_item = MenuItem::new("Mostrar/Esconder Console", true, None);
    let open_logs_item = MenuItem::new("Abrir Pasta de Logs", true, None);
    let quit_item = MenuItem::new("Sair", true, None);

    tray_menu.append_items(&[
        &show_hide_item,
        &open_logs_item,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ])?;

    // 2. Create Icon (32x32 Green dot)
    let icon = create_simple_icon();

    // 3. Initialize Tray Icon
    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("Monitor de Internet")
        .with_icon(icon)
        .build()?;

    // 4. Spawn Monitoring Loop
    tokio::spawn(async move {
        if let Err(e) = run_monitor().await {
            eprintln!("Monitor Erro: {}", e);
        }
    });

    // 5. Run GUI Event Loop (tao)
    let event_loop = EventLoopBuilder::new().build();
    let menu_channel = MenuEvent::receiver();
    let mut console_visible = false; // Initial state matches step 0

    event_loop.run(move |_event, _, control_flow| {
        *control_flow = ControlFlow::Poll;

        if let Ok(event) = menu_channel.try_recv() {
            if event.id == show_hide_item.id() {
                console_visible = !console_visible;
                set_console_visibility(console_visible);
            } else if event.id == open_logs_item.id() {
                let _ = Command::new("explorer").arg(".").spawn();
            } else if event.id == quit_item.id() {
                *control_flow = ControlFlow::Exit;
            }
        }
    });
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

async fn run_monitor() -> Result<()> {
    let client = Client::builder()
        .tcp_keepalive(Some(TokioDuration::from_secs(60)))
        .timeout(TokioDuration::from_secs(2))
        .build()?;

    let mut ctx = get_network_context(&client).await;
    let mut tracker = IncidentTracker {
        last_outage_start: None,
        instability_count: 0,
        last_incidents: Vec::new(),
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

    println!("--- Monitor de Estabilidade de Internet (v2) Ativo ---");
    println!("DICA: Use o ícone na bandeja para esconder esta janela.");
    println!("AVISO: Clicar no 'X' desta janela fechará o programa permanentemente.");
    println!("---------------------------------------------------------");

    loop {
        let now = Local::now();
        
        // 1. Connectivity Tests
        let dns_start = Instant::now();
        let dns_res = lookup_host("www.google.com");
        let dns_status = if dns_res.is_ok() { "OK" } else { "FAIL" };
        let dns_time = dns_start.elapsed().as_millis();

        let http_start = Instant::now();
        let http_res = client.head("https://www.google.com").send().await;
        let (http_status, http_code, http_rtt) = match http_res {
            Ok(resp) => ("OK", resp.status().as_u16().to_string(), http_start.elapsed().as_millis()),
            Err(e) => ("FAIL", format!("{:?}", e.status().map(|s| s.as_u16()).unwrap_or(0)), 0),
        };

        let ip_direct_res = client.head("http://1.1.1.1").send().await;
        let ip_direct_status = if ip_direct_res.is_ok() { "OK" } else { "FAIL" };

        let is_up = http_status == "OK";

        // 2. Network Context (Check for changes every 10 seconds or on recovery)
        if now.second() % 10 == 0 || (is_up && tracker.last_outage_start.is_some()) {
            let new_ctx = get_network_context(&client).await;
            if new_ctx != ctx {
                log_to_file("network_context.txt", &format!(
                    "[{}] MUDANÇA: Int:{} | GW:{} | Ext:{} | SSID:{}",
                    now.format("%Y-%m-%d %H:%M:%S"), new_ctx.internal_ip, new_ctx.gateway, new_ctx.external_ip, new_ctx.wifi_ssid
                ));
                ctx = new_ctx;
            }
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
            "[{}] HTTP:{} (Code:{}, RTT:{}ms) | DNS:{} ({}ms) | IP_Direct:{}",
            now.format("%Y-%m-%d %H:%M:%S"), http_status, http_code, http_rtt, dns_status, dns_time, ip_direct_status
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
    let output = Command::new("ipconfig").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found_gateway = None;
    
    for line in stdout.lines() {
        if line.contains("Default Gateway") || line.contains("Gateway Padrão") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 && !parts[1].trim().is_empty() {
                found_gateway = Some(parts[1].trim().to_string());
                break;
            }
        }
    }
    
    found_gateway.ok_or_else(|| anyhow!("Gateway não encontrado"))
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
    
    if let Err(e) = file.sync_all() {
        eprintln!("Erro ao sincronizar arquivo {:?} com o disco: {}", path, e);
    }
}
