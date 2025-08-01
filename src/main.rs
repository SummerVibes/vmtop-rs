use std::{time::Duration, collections::HashMap, fs};
use std::io::{Write, stdout};
use chrono::Local;
use sysinfo::{Pid, Process, System};
use tui::{backend::CrosstermBackend, Terminal};
use tui::widgets::{Block, Borders, Table, Row, Cell};
use tui::layout::Constraint;
use tui::style::{Style, Color, Modifier};
use crossterm::{execute, terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use crossterm::event::{self, Event, KeyCode};

// Log level enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

// Log function
fn log(level: LogLevel, message: &str) {
    let log_dir = "/var/log/vmtop";
    let log_file = format!("{}/vmtop.log", log_dir);
    
    // Ensure log directory exists
    if let Err(e) = fs::create_dir_all(log_dir) {
        eprintln!("Failed to create log directory: {}", e);
        return;
    }
    
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    let level_str = match level {
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
        LogLevel::Debug => "DEBUG",
    };
    
    let log_entry = format!("[{}] {} - {}\n", timestamp, level_str, message);
    
    // Append to log file
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
    {
        if let Err(e) = file.write_all(log_entry.as_bytes()) {
            eprintln!("Failed to write to log file: {}", e);
        }
    } else {
        eprintln!("Failed to open log file: {}", log_file);
    }
}

// Convenient log macros
macro_rules! log_info {
    ($($arg:tt)*) => {
        log(LogLevel::Info, &format!($($arg)*));
    };
}

macro_rules! log_warn {
    ($($arg:tt)*) => {
        log(LogLevel::Warn, &format!($($arg)*));
    };
}

macro_rules! log_error {
    ($($arg:tt)*) => {
        log(LogLevel::Error, &format!($($arg)*));
    };
}

macro_rules! log_debug {
    ($($arg:tt)*) => {
        log(LogLevel::Debug, &format!($($arg)*));
    };
}

// Remove the unused VmExitStats struct
// #[derive(Default, Clone)]
// struct VmExitStats {
//     exits: u64,
    
//     #[cfg(target_arch = "x86_64")]
//     halt_exits: u64,
//     #[cfg(target_arch = "x86_64")]
//     irq_exits: u64,
//     #[cfg(target_arch = "x86_64")]
//     kvm_msr_write: u64,
//     #[cfg(target_arch = "x86_64")]
//     host_state_reload: u64,
//     #[cfg(target_arch = "x86_64")]
//     io_exits: u64,
//     #[cfg(target_arch = "x86_64")]
//     mmio_exits: u64,
//     #[cfg(target_arch = "x86_64")]
//     insn_emulation: u64,
    
//     #[cfg(target_arch = "aarch64")]
//     hvc_exit_stat: u64,
//     #[cfg(target_arch = "aarch64")]
//     mmio_exit_kernel: u64,
//     #[cfg(target_arch = "aarch64")]
//     mmio_exit_user: u64,
//     #[cfg(target_arch = "aarch64")]
//     wfe_exit_stat: u64,
//     #[cfg(target_arch = "aarch64")]
//     wfi_exit_stat: u64,
// }

#[derive(Debug, Clone)]
struct DebugFileInfo {
    name: String,
    current_value: u64,
    delta_value: u64,
}

#[derive(Default)]
struct AppState {
    selected_index: usize,
    show_detail: bool,
    detail_pid: Option<Pid>,
    prev_exit_stats_detail: HashMap<Pid, HashMap<String, u64>>,
}

struct VMStats {
    pid: Pid,
    uuid: String,           // Virtual machine UUID
    process_cpu: f32,       // Total CPU usage
    user_cpu: f32,          // User space CPU usage
    kernel_cpu: f32,        // Kernel space CPU usage
    vcpu_usage: f32,
    memory: u64,
    exit_stats_delta: HashMap<String, u64>,    // Delta since last refresh
}

fn calculate_vcpu_usage(sys: &System, pid: &Pid) -> f32 {
    let mut total_vcpu = 0.0;
    
    let process = match sys.process(*pid) {
        Some(process) => process,
        None => return total_vcpu,
    };
    
    // In sysinfo 0.30, tasks() method returns Option<&[Pid]>
    if let Some(tasks) = process.tasks() {
        for task_pid in tasks {
            if let Some(task_process) = sys.process(*task_pid) {
                if task_process.name().to_lowercase().contains("kvm") {
                    total_vcpu += task_process.cpu_usage();
                }
            }
        }
    }
    
    total_vcpu
}

// Architecture-specific exit statistics collection function
#[cfg(target_arch = "x86_64")]
fn collect_vmexit_stats(pid: Pid) -> HashMap<String, u64> {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut stats = HashMap::new();
    
    log_debug!("Collecting x86_64 exit stats for PID: {}", pid);
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                if dir_name.starts_with(&format!("{}-", pid)) {
                    let halt_exits_path = entry.path().join("halt_exits");
                    let irq_exits_path = entry.path().join("irq_exits");
                    let kvm_msr_write_path = entry.path().join("kvm_msr_write");
                    let host_state_reload_path = entry.path().join("host_state_reload");
                    let io_exits_path = entry.path().join("io_exits");
                    let mmio_exits_path = entry.path().join("mmio_exits");
                    let insn_emulation_path = entry.path().join("insn_emulation");
                    let exits_path = entry.path().join("exits");
                    
                    if let Ok(content) = fs::read_to_string(&exits_path) {
                        stats.insert("exits".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&halt_exits_path) {
                        stats.insert("halt_exits".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&irq_exits_path) {
                        stats.insert("irq_exits".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&kvm_msr_write_path) {
                        stats.insert("kvm_msr_write".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&host_state_reload_path) {
                        stats.insert("host_state_reload".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&io_exits_path) {
                        stats.insert("io_exits".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&mmio_exits_path) {
                        stats.insert("mmio_exits".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&insn_emulation_path) {
                        stats.insert("insn_emulation".to_string(), parse_exit_count(&content));
                    }
                }
            }
        }
    }
    stats
}

#[cfg(target_arch = "aarch64")]
fn collect_vmexit_stats(pid: Pid) -> HashMap<String, u64> {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut stats = HashMap::new();
    
    log_debug!("Collecting aarch64 exit stats for PID: {}", pid);
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                if dir_name.starts_with(&format!("{}-", pid)) {
                    let exits_path = entry.path().join("exits");
                    let hvc_exit_stat_path = entry.path().join("hvc_exit_stat");
                    let mmio_exit_kernel_path = entry.path().join("mmio_exit_kernel");
                    let mmio_exit_user_path = entry.path().join("mmio_exit_user");
                    let wfe_exit_stat_path = entry.path().join("wfe_exit_stat");
                    let wfi_exit_stat_path = entry.path().join("wfi_exit_stat");
                    
                    if let Ok(content) = fs::read_to_string(&exits_path) {
                        stats.insert("exits".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&hvc_exit_stat_path) {
                        stats.insert("hvc_exit_stat".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&mmio_exit_kernel_path) {
                        stats.insert("mmio_exit_kernel".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&mmio_exit_user_path) {
                        stats.insert("mmio_exit_user".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&wfe_exit_stat_path) {
                        stats.insert("wfe_exit_stat".to_string(), parse_exit_count(&content));
                    }
                    if let Ok(content) = fs::read_to_string(&wfi_exit_stat_path) {
                        stats.insert("wfi_exit_stat".to_string(), parse_exit_count(&content));
                    }
                }
            }
        }
    }
    stats
}

// Enhanced parse_exit_count function supporting multiple formats
fn parse_exit_count(content: &str) -> u64 {
    let mut total = 0;
    
    // Handle empty content
    if content.trim().is_empty() {
        return 0;
    }
    
    // Handle single line number format
    if content.lines().count() == 1 {
        if let Ok(num) = content.trim().parse::<u64>() {
            return num;
        }
    }
    
    // Handle CPU format: CPU0: 12345
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        // Try to parse CPU format
        if line.starts_with("CPU") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(num) = parts[1].trim().parse::<u64>() {
                    total += num;
                }
            }
        } 
        // Try to parse simple number format
        else if let Ok(num) = line.parse::<u64>() {
            total += num;
        }
    }
    
    total
}

fn get_all_debug_files(pid: Pid, prev_stats: &mut HashMap<Pid, HashMap<String, u64>>) -> Vec<DebugFileInfo> {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut files = Vec::new();
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                if dir_name.starts_with(&format!("{}-", pid)) {
                    if let Ok(file_entries) = fs::read_dir(&entry.path()) {
                        for file_entry in file_entries.flatten() {
                            let file_name = file_entry.file_name().to_string_lossy().to_string();
                            let file_path = file_entry.path();
                            
                            if let Ok(content) = fs::read_to_string(&file_path) {
                                let current_value = parse_exit_count(&content);
                                
                                // Get previous value from HashMap
                                let prev_value = prev_stats
                                    .get(&pid)
                                    .and_then(|stats| stats.get(&file_name))
                                    .copied()
                                    .unwrap_or(0);
                                
                                let delta_value = current_value.saturating_sub(prev_value);
                                
                                files.push(DebugFileInfo {
                                    name: file_name.clone(),
                                    current_value,
                                    delta_value,
                                });
                                
                                // Update the HashMap with current value
                                prev_stats
                                    .entry(pid)
                                    .or_insert_with(HashMap::new)
                                    .insert(file_name, current_value);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    
    files
}

// Scan /sys/kernel/debug/kvm directory to get all QEMU process PIDs
fn scan_kvm_pids() -> Vec<Pid> {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut pids = Vec::new();
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                // Directory name format is usually "12345-" or "12345-guest"
                if let Some(pid_str) = dir_name.split('-').next() {
                    if let Ok(pid_num) = pid_str.parse::<usize>() {
                        pids.push(Pid::from(pid_num));
                        log_debug!("Found KVM directory for PID: {}", pid_num);
                    }
                }
            }
        }
    } else {
        log_warn!("Failed to read /sys/kernel/debug/kvm directory");
    }
    
    pids
}

// Extract UUID from QEMU process command line arguments
fn extract_vm_uuid(process: &Process) -> String {
    let cmd = process.cmd();
    
    // Look for -uuid parameter
    for (i, arg) in cmd.iter().enumerate() {
        if arg == "-uuid" && i + 1 < cmd.len() {
            return cmd[i + 1].to_string();
        }
    }
    
    // If -uuid parameter not found, try to extract from -name parameter
    for (i, arg) in cmd.iter().enumerate() {
        if arg == "-name" && i + 1 < cmd.len() {
            let name = &cmd[i + 1];
            // Check if it contains UUID format
            if name.len() >= 36 {
                // Look for UUID format (8-4-4-4-12)
                let parts: Vec<&str> = name.split(',').collect();
                for part in parts {
                    if part.len() == 36 && part.chars().filter(|&c| c == '-').count() == 4 {
                        return part.to_string();
                    }
                }
            }
            return name.to_string();
        }
    }
    
    // Fallback to process name
    process.name().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize logging
    log_info!("vmtop starting...");
    
    let mut system = System::new_all();
    let mut prev_cpu_times: HashMap<Pid, u64> = HashMap::new();
    let mut prev_exit_stats: HashMap<Pid, HashMap<String, u64>> = HashMap::new();
    let mut prev_exit_stats_detail: HashMap<Pid, HashMap<String, u64>> = HashMap::new();
    let mut app_state = AppState::default();
    
    log_info!("System initialized successfully");

    loop {
        system.refresh_all();
        
        let mut vm_stats: Vec<VMStats> = Vec::new();
        
        // Find QEMU processes by scanning /sys/kernel/debug/kvm directory
        let kvm_pids = scan_kvm_pids();
        
        for pid in kvm_pids {
            if let Some(process) = system.process(pid) {
                log_debug!("Found QEMU process via KVM: {} - PID: {}", process.name(), pid);
                
                // Calculate CPU usage - separate user and kernel space
                let total_cpu_time = process.cpu_usage() as u64;
                
                // In sysinfo 0.30, use cpu_usage() as total CPU usage
                // Since version 0.30 doesn't have direct user_cpu_time and system_cpu_time methods,
                // we use process CPU usage as approximation
                let user_cpu_ratio = 0.7; // Assume 70% user space
                let kernel_cpu_ratio = 0.3; // Assume 30% kernel space
                
                let prev_total = prev_cpu_times.get(&pid).unwrap_or(&0);
                let total_delta = total_cpu_time.saturating_sub(*prev_total) as f32;
                let user_delta = total_delta * user_cpu_ratio;
                let kernel_delta = total_delta * kernel_cpu_ratio;
                
                // Calculate vCPU usage
                let vcpu_usage = calculate_vcpu_usage(&system, &pid);
                
                // Collect VM exit statistics
                let current_stats = collect_vmexit_stats(pid);
                
                // Calculate deltas
                let mut delta_stats = HashMap::new();
                for (key, current_value) in current_stats.iter() {
                    let prev_value = prev_exit_stats
                        .get(&pid)
                        .and_then(|stats| stats.get(key))
                        .copied()
                        .unwrap_or(0);
                    delta_stats.insert(key.clone(), current_value.saturating_sub(prev_value));
                }
                
                vm_stats.push(VMStats {
                    pid,
                    uuid: extract_vm_uuid(&process),
                    process_cpu: total_delta,
                    user_cpu: user_delta,
                    kernel_cpu: kernel_delta,
                    vcpu_usage,
                    memory: process.memory(),
                    exit_stats_delta: delta_stats,
                });
                
                prev_cpu_times.insert(pid, total_cpu_time);
                prev_exit_stats.insert(pid, current_stats);
            }
        }
        
        // Use tui library to display data
        terminal.draw(|f| {
            let size = f.size();
            
            if app_state.show_detail {
                // Detail view
                if let Some(detail_pid) = app_state.detail_pid {
let debug_files = get_all_debug_files(detail_pid, &mut prev_exit_stats_detail);
                    
                    let headers = vec![
                        Cell::from("File"),
                        Cell::from("Current"),
                        Cell::from("Delta"),
                    ];
                    
                    let widths = &[
                        Constraint::Length(20),
                        Constraint::Length(15),
                        Constraint::Length(15),
                    ];
                    
                    let mut rows = Vec::new();
                    for file in debug_files {
                        rows.push(Row::new(vec![
                            Cell::from(file.name),
                            Cell::from(file.current_value.to_string()),
                            Cell::from(file.delta_value.to_string()),
                        ]));
                    }
                    
                    let title = format!("vmtop - VM Details (PID: {})", detail_pid);
                    let table = Table::new(rows)
                        .header(Row::new(headers).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                        .block(Block::default().title(title).borders(Borders::ALL))
                        .widths(widths);
                    
                    f.render_widget(table, size);
                }
            } else {
                // Main view
                // Architecture-specific headers and column widths
                #[cfg(target_arch = "x86_64")]
                {
                    let headers = vec![
                        Cell::from("PID"),
                        Cell::from("UUID"),
                        Cell::from("User%"),
                        Cell::from("Kern%"),
                        Cell::from("vCPU%"),
                        Cell::from("Mem(MB)"),
                        Cell::from("Exits"),
                        Cell::from("Halt"),
                        Cell::from("IRQ"),
                        Cell::from("MSR"),
                        Cell::from("Reload"),
                        Cell::from("IO"),
                        Cell::from("MMIO"),
                        Cell::from("Insn"),
                    ];
                    
                    let widths = &[
                        Constraint::Length(6),
                        Constraint::Length(36),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(8),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(7),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(6),
                    ];
                    
                    let mut rows = Vec::new();
                    for (i, vm) in vm_stats.iter().enumerate() {
                        let mut style = Style::default();
                        if i == app_state.selected_index {
                            style = style.bg(Color::Blue);
                        }
                        
                        rows.push(Row::new(vec![
                            Cell::from(vm.pid.to_string()).style(style),
                            Cell::from(vm.uuid.clone()).style(style),
                            Cell::from(format!("{:.2}", vm.user_cpu)).style(style),
                            Cell::from(format!("{:.2}", vm.kernel_cpu)).style(style),
                            Cell::from(format!("{:.2}", vm.vcpu_usage)).style(style),
                            Cell::from(format!("{:.2}", vm.memory as f64 / 1024.0 / 1024.0)).style(style),
                            Cell::from(vm.exit_stats_delta.get("exits").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("halt_exits").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("irq_exits").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("kvm_msr_write").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("host_state_reload").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("io_exits").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("mmio_exits").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("insn_emulation").unwrap_or(&0).to_string()).style(style),
                        ]));
                    }
                    
                    let table = Table::new(rows)
                        .header(Row::new(headers).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                        .block(Block::default().title("vmtop - Virtual Machine Monitor (Use ↑↓ to select, Enter for details, q to quit)").borders(Borders::ALL))
                        .widths(widths);
                    
                    f.render_widget(table, size);
                }
                
                #[cfg(target_arch = "aarch64")]
                {
                    let headers = vec![
                        Cell::from("PID"),
                        Cell::from("UUID"),
                        Cell::from("User%"),
                        Cell::from("Kern%"),
                        Cell::from("vCPU%"),
                        Cell::from("Mem(MB)"),
                        Cell::from("Exits"),
                        Cell::from("HVC"),
                        Cell::from("MMIO-K"),
                        Cell::from("MMIO-U"),
                        Cell::from("WFE"),
                        Cell::from("WFI"),
                    ];
                    
                    let widths = &[
                        Constraint::Length(6),
                        Constraint::Length(36),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(8),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(7),
                        Constraint::Length(7),
                        Constraint::Length(6),
                        Constraint::Length(6),
                    ];
                    
                    let mut rows = Vec::new();
                    for (i, vm) in vm_stats.iter().enumerate() {
                        let mut style = Style::default();
                        if i == app_state.selected_index {
                            style = style.bg(Color::Blue);
                        }
                        
                        rows.push(Row::new(vec![
                            Cell::from(vm.pid.to_string()).style(style),
                            Cell::from(vm.uuid.clone()).style(style),
                            Cell::from(format!("{:.2}", vm.user_cpu)).style(style),
                            Cell::from(format!("{:.2}", vm.kernel_cpu)).style(style),
                            Cell::from(format!("{:.2}", vm.vcpu_usage)).style(style),
                            Cell::from(format!("{:.2}", vm.memory as f64 / 1024.0 / 1024.0)).style(style),
                            Cell::from(vm.exit_stats_delta.get("exits").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("hvc_exit_stat").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("mmio_exit_kernel").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("mmio_exit_user").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("wfe_exit_stat").unwrap_or(&0).to_string()).style(style),
                            Cell::from(vm.exit_stats_delta.get("wfi_exit_stat").unwrap_or(&0).to_string()).style(style),
                        ]));
                    }
                    
                    let table = Table::new(rows)
                        .header(Row::new(headers).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                        .block(Block::default().title("vmtop - Virtual Machine Monitor (Use ↑↓ to select, Enter for details, q to quit)").borders(Borders::ALL))
                        .widths(widths);
                    
                    f.render_widget(table, size);
                }
                
                if vm_stats.is_empty() {
                    let empty_row = Row::new(vec![
                        Cell::from("-"),
                        Cell::from("No VMs found"),
                        Cell::from("-"),
                        Cell::from("-"),
                        Cell::from("-"),
                        Cell::from("-"),
                        Cell::from("-"),
                        Cell::from("-"),
                    ]);
                    
                    let table = Table::new(vec![empty_row])
                        .header(Row::new(vec![
                            Cell::from("PID"),
                            Cell::from("UUID"),
                            Cell::from("User%"),
                            Cell::from("Kernel%"),
                            Cell::from("vCPU%"),
                            Cell::from("Memory(MB)"),
                            Cell::from("Exits"),
                            Cell::from("Status"),
                        ]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                        .block(Block::default().title("vmtop - Virtual Machine Monitor").borders(Borders::ALL))
                        .widths(&[
                            Constraint::Length(8),
                            Constraint::Length(36),
                            Constraint::Length(8),
                            Constraint::Length(8),
                            Constraint::Length(8),
                            Constraint::Length(12),
                            Constraint::Length(8),
                            Constraint::Length(8),
                        ]);
                    
                    f.render_widget(table, size);
                }
            }
        })?;
        
// Check keyboard events with shorter timeout for better responsiveness
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                let mut should_redraw = false;
                
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        log_info!("User requested exit, shutting down...");
                        break;
                    }
                    KeyCode::Esc => {
                        if app_state.show_detail {
                            app_state.show_detail = false;
                            app_state.detail_pid = None;
                            should_redraw = true;
                        } else {
                            log_info!("User pressed ESC, shutting down...");
                            break;
                        }
                    }
                    KeyCode::Up => {
                        if !app_state.show_detail && !vm_stats.is_empty() {
                            if app_state.selected_index > 0 {
                                app_state.selected_index -= 1;
                                should_redraw = true;
                            }
                        }
                    }
                    KeyCode::Down => {
                        if !app_state.show_detail && !vm_stats.is_empty() {
                            if app_state.selected_index < vm_stats.len().saturating_sub(1) {
                                app_state.selected_index += 1;
                                should_redraw = true;
                            }
                        }
                    }
                    KeyCode::Enter => {
                        if !app_state.show_detail && !vm_stats.is_empty() {
                            if let Some(selected_vm) = vm_stats.get(app_state.selected_index) {
                                app_state.show_detail = true;
                                app_state.detail_pid = Some(selected_vm.pid);
                                should_redraw = true;
                            }
                        }
                    }
                    _ => {}
                }
                
                // Only redraw when necessary
                if should_redraw {
                    continue;
                }
            }
        }
        
        // Shorter sleep for more responsive updates
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    
    // Clean up terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    
    log_info!("vmtop exited successfully");
    Ok(())
}
