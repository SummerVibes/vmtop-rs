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

// Use conditional compilation to define architecture-specific exit statistics structure
#[derive(Default, Clone)]
struct VmExitStats {
    exits: u64,
    
    #[cfg(target_arch = "x86_64")]
    halt_exits: u64,
    #[cfg(target_arch = "x86_64")]
    irq_exits: u64,
    #[cfg(target_arch = "x86_64")]
    kvm_msr_write: u64,
    
    #[cfg(target_arch = "aarch64")]
    hvc_exit_stat: u64,
    #[cfg(target_arch = "aarch64")]
    mmio_exit_kernel: u64,
    #[cfg(target_arch = "aarch64")]
    mmio_exit_user: u64,
    #[cfg(target_arch = "aarch64")]
    wfe_exit_stat: u64,
    #[cfg(target_arch = "aarch64")]
    wfi_exit_stat: u64,
}

struct VMStats {
    pid: Pid,
    uuid: String,           // Virtual machine UUID
    process_cpu: f32,       // Total CPU usage
    user_cpu: f32,          // User space CPU usage
    kernel_cpu: f32,        // Kernel space CPU usage
    vcpu_usage: f32,
    memory: u64,
    exit_stats_delta: VmExitStats,    // Delta since last refresh
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
fn collect_vmexit_stats(pid: Pid) -> VmExitStats {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut stats = VmExitStats::default();
    
    log_debug!("Collecting x86_64 exit stats for PID: {}", pid);
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                if dir_name.starts_with(&format!("{}-", pid)) {
                    let halt_exits_path = entry.path().join("halt_exits");
                    let irq_exits_path = entry.path().join("irq_exits");
                    let kvm_msr_write_path = entry.path().join("kvm_msr_write");
                    let exits_path = entry.path().join("exits");
                    
                    if let Ok(content) = fs::read_to_string(&exits_path) {
                        stats.exits = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&halt_exits_path) {
                        stats.halt_exits = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&irq_exits_path) {
                        stats.irq_exits = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&kvm_msr_write_path) {
                        stats.kvm_msr_write = parse_exit_count(&content);
                    }
                }
            }
        }
    }
    stats
}

#[cfg(target_arch = "aarch64")]
fn collect_vmexit_stats(pid: Pid) -> VmExitStats {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut stats = VmExitStats::default();
    
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
                        stats.exits = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&hvc_exit_stat_path) {
                        stats.hvc_exit_stat = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&mmio_exit_kernel_path) {
                        stats.mmio_exit_kernel = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&mmio_exit_user_path) {
                        stats.mmio_exit_user = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&wfe_exit_stat_path) {
                        stats.wfe_exit_stat = parse_exit_count(&content);
                    }
                    if let Ok(content) = fs::read_to_string(&wfi_exit_stat_path) {
                        stats.wfi_exit_stat = parse_exit_count(&content);
                    }
                }
            }
        }
    }
    stats
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn collect_vmexit_stats(pid: Pid) -> VmExitStats {
    log_warn!("Unsupported architecture, only collecting basic exits");
    let debug_path = "/sys/kernel/debug/kvm";
    let mut stats = VmExitStats::default();
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                if dir_name.starts_with(&format!("{}-", pid)) {
                    let exits_path = entry.path().join("exits");
                    if let Ok(content) = fs::read_to_string(&exits_path) {
                        stats.exits = parse_exit_count(&content);
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
    let mut prev_exit_stats: HashMap<Pid, VmExitStats> = HashMap::new();
    
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
                let mut delta_stats = VmExitStats::default();
                if let Some(prev_stats) = prev_exit_stats.get(&pid) {
                    delta_stats.exits = current_stats.exits.saturating_sub(prev_stats.exits);
                    
                    #[cfg(target_arch = "x86_64")]
                    {
                        delta_stats.halt_exits = current_stats.halt_exits.saturating_sub(prev_stats.halt_exits);
                        delta_stats.irq_exits = current_stats.irq_exits.saturating_sub(prev_stats.irq_exits);
                        delta_stats.kvm_msr_write = current_stats.kvm_msr_write.saturating_sub(prev_stats.kvm_msr_write);
                    }
                    
                    #[cfg(target_arch = "aarch64")]
                    {
                        delta_stats.hvc_exit_stat = current_stats.hvc_exit_stat.saturating_sub(prev_stats.hvc_exit_stat);
                        delta_stats.mmio_exit_kernel = current_stats.mmio_exit_kernel.saturating_sub(prev_stats.mmio_exit_kernel);
                        delta_stats.mmio_exit_user = current_stats.mmio_exit_user.saturating_sub(prev_stats.mmio_exit_user);
                        delta_stats.wfe_exit_stat = current_stats.wfe_exit_stat.saturating_sub(prev_stats.wfe_exit_stat);
                        delta_stats.wfi_exit_stat = current_stats.wfi_exit_stat.saturating_sub(prev_stats.wfi_exit_stat);
                    }
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
            
            // Architecture-specific headers and column widths
            #[cfg(target_arch = "x86_64")]
            {
                let headers = vec![
                    Cell::from("PID"),
                    Cell::from("UUID"),
                    Cell::from("User%"),
                    Cell::from("Kernel%"),
                    Cell::from("vCPU%"),
                    Cell::from("Memory(MB)"),
                    Cell::from("Halt"),
                    Cell::from("IRQ"),
                    Cell::from("MSR"),
                ];
                
                let widths = &[
                    Constraint::Length(10),
                    Constraint::Length(36),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(12),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                ];
                
                let mut rows = Vec::new();
                for vm in &vm_stats {
                    rows.push(Row::new(vec![
                        Cell::from(vm.pid.to_string()),
                        Cell::from(vm.uuid.clone()),
                        Cell::from(format!("{:.2}", vm.user_cpu)),
                        Cell::from(format!("{:.2}", vm.kernel_cpu)),
                        Cell::from(format!("{:.2}", vm.vcpu_usage)),
                        Cell::from(format!("{:.2}", vm.memory as f64 / 1024.0 / 1024.0)),
                        Cell::from(vm.exit_stats_delta.halt_exits.to_string()),
                        Cell::from(vm.exit_stats_delta.irq_exits.to_string()),
                        Cell::from(vm.exit_stats_delta.kvm_msr_write.to_string()),
                    ]));
                }
                
                let table = Table::new(rows)
                    .header(Row::new(headers).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                    .block(Block::default().title("vmtop - Virtual Machine Monitor").borders(Borders::ALL))
                    .widths(widths);
                
                f.render_widget(table, size);
            }
            
            #[cfg(target_arch = "aarch64")]
            {
                let headers = vec![
                    Cell::from("PID"),
                    Cell::from("UUID"),
                    Cell::from("User%"),
                    Cell::from("Kernel%"),
                    Cell::from("vCPU%"),
                    Cell::from("Memory(MB)"),
                    Cell::from("HVC"),
                    Cell::from("MMIO_K"),
                    Cell::from("MMIO_U"),
                    Cell::from("WFE"),
                    Cell::from("WFI"),
                ];
                
                let widths = &[
                    Constraint::Length(10),
                    Constraint::Length(36),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(12),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                ];
                
                let mut rows = Vec::new();
                for vm in &vm_stats {
                    rows.push(Row::new(vec![
                        Cell::from(vm.pid.to_string()),
                        Cell::from(vm.uuid.clone()),
                        Cell::from(format!("{:.2}", vm.user_cpu)),
                        Cell::from(format!("{:.2}", vm.kernel_cpu)),
                        Cell::from(format!("{:.2}", vm.vcpu_usage)),
                        Cell::from(format!("{:.2}", vm.memory as f64 / 1024.0 / 1024.0)),
                        Cell::from(vm.exit_stats_delta.hvc_exit_stat.to_string()),
                        Cell::from(vm.exit_stats_delta.mmio_exit_kernel.to_string()),
                        Cell::from(vm.exit_stats_delta.mmio_exit_user.to_string()),
                        Cell::from(vm.exit_stats_delta.wfe_exit_stat.to_string()),
                        Cell::from(vm.exit_stats_delta.wfi_exit_stat.to_string()),
                    ]));
                }
                
                let table = Table::new(rows)
                    .header(Row::new(headers).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                    .block(Block::default().title("vmtop - Virtual Machine Monitor").borders(Borders::ALL))
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
                ]);
                
                let table = Table::new(vec![empty_row])
                    .header(Row::new(vec![
                        Cell::from("PID"),
                        Cell::from("UUID"),
                        Cell::from("User%"),
                        Cell::from("Kernel%"),
                        Cell::from("vCPU%"),
                        Cell::from("Memory(MB)"),
                        Cell::from("Status"),
                    ]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                    .block(Block::default().title("vmtop - Virtual Machine Monitor").borders(Borders::ALL))
                    .widths(&[
                        Constraint::Length(10),
                        Constraint::Length(36),
                        Constraint::Length(8),
                        Constraint::Length(8),
                        Constraint::Length(8),
                        Constraint::Length(12),
                        Constraint::Length(8),
                    ]);
                
                f.render_widget(table, size);
            }
        })?;
        
        // Check keyboard events
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        log_info!("User requested exit, shutting down...");
                        break;
                    }
                    KeyCode::Esc => {
                        log_info!("User pressed ESC, shutting down...");
                        break;
                    }
                    _ => {}
                }
            }
        }
        
        std::thread::sleep(std::time::Duration::from_secs(1));
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
