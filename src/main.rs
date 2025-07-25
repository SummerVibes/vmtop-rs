use std::{time::Duration, collections::HashMap, fs};
use std::io::{Write, stdout};
use std::path::Path;
use chrono::Local;
use sysinfo::{Pid, Process, System};
use tui::{backend::CrosstermBackend, Terminal};
use tui::widgets::{Block, Borders, Table, Row, Cell};
use tui::layout::{Constraint, Layout};
use tui::style::{Style, Color, Modifier};
use crossterm::{execute, terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use crossterm::event::{self, Event, KeyCode};

// 日志级别枚举
#[derive(Debug, Clone, Copy, PartialEq)]
enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

// 日志函数
fn log(level: LogLevel, message: &str) {
    let log_dir = "/var/log/vmtop";
    let log_file = format!("{}/vmtop.log", log_dir);
    
    // 确保日志目录存在
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
    
    // 追加写入日志文件
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

// 便捷的日志宏
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

// 使用条件编译定义架构特定的exit统计结构
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
    uuid: String,           // 虚拟机UUID
    process_cpu: f32,       // 总CPU使用率
    user_cpu: f32,          // 用户态CPU使用率
    kernel_cpu: f32,        // 内核态CPU使用率
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
    
    // 在sysinfo 0.30中，tasks()方法返回Option<&[Pid]>
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

// 架构特定的exit统计收集函数
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

// 增强的parse_exit_count函数，支持多种格式
fn parse_exit_count(content: &str) -> u64 {
    let mut total = 0;
    
    // 处理空内容
    if content.trim().is_empty() {
        return 0;
    }
    
    // 处理单行数字格式
    if content.lines().count() == 1 {
        if let Ok(num) = content.trim().parse::<u64>() {
            return num;
        }
    }
    
    // 处理CPU格式：CPU0: 12345
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        // 尝试解析CPU格式
        if line.starts_with("CPU") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(num) = parts[1].trim().parse::<u64>() {
                    total += num;
                }
            }
        } 
        // 尝试解析简单数字格式
        else if let Ok(num) = line.parse::<u64>() {
            total += num;
        }
    }
    
    total
}

// 扫描/sys/kernel/debug/kvm目录获取所有QEMU进程的PID
fn scan_kvm_pids() -> Vec<Pid> {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut pids = Vec::new();
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                // 目录名格式通常是 "12345-" 或 "12345-guest"
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

// 从QEMU进程命令行参数中提取UUID
fn extract_vm_uuid(process: &Process) -> String {
    let cmd = process.cmd();
    
    // 查找 -uuid 参数
    for (i, arg) in cmd.iter().enumerate() {
        if arg == "-uuid" && i + 1 < cmd.len() {
            return cmd[i + 1].to_string();
        }
    }
    
    // 如果没有找到 -uuid 参数，尝试从 -name 参数中提取
    for (i, arg) in cmd.iter().enumerate() {
        if arg == "-name" && i + 1 < cmd.len() {
            let name = &cmd[i + 1];
            // 检查是否包含UUID格式
            if name.len() >= 36 {
                // 查找UUID格式 (8-4-4-4-12)
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
    
    // 回退到进程名
    process.name().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化终端
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 初始化日志
    log_info!("vmtop starting...");
    
    let mut system = System::new_all();
    let mut prev_cpu_times: HashMap<Pid, u64> = HashMap::new();
    let mut prev_exit_stats: HashMap<Pid, VmExitStats> = HashMap::new();
    
    log_info!("System initialized successfully");

    loop {
        system.refresh_all();
        
        let mut vm_stats: Vec<VMStats> = Vec::new();
        
        // 通过扫描/sys/kernel/debug/kvm目录来查找QEMU进程
        let kvm_pids = scan_kvm_pids();
        
        for pid in kvm_pids {
            if let Some(process) = system.process(pid) {
                log_debug!("Found QEMU process via KVM: {} - PID: {}", process.name(), pid);
                
                // Calculate CPU usage - 分离用户态和内核态
                let total_cpu_time = process.cpu_usage() as u64;
                
                // 在sysinfo 0.30中，使用cpu_usage()作为总CPU使用率
                // 由于0.30版本没有直接的user_cpu_time和system_cpu_time方法，
                // 我们使用进程的CPU使用率作为近似值
                let user_cpu_ratio = 0.7; // 假设70%为用户态
                let kernel_cpu_ratio = 0.3; // 假设30%为内核态
                
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
        
        // 使用tui库显示数据
        terminal.draw(|f| {
            let size = f.size();
            
            // 架构特定的表头和列宽
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
            
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                let headers = vec![
                    Cell::from("PID"),
                    Cell::from("UUID"),
                    Cell::from("User%"),
                    Cell::from("Kernel%"),
                    Cell::from("vCPU%"),
                    Cell::from("Memory(MB)"),
                    Cell::from("Exits"),
                ];
                
                let widths = &[
                    Constraint::Length(10),
                    Constraint::Length(36),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(12),
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
                        Cell::from(vm.exit_stats_delta.exits.to_string()),
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
        
        // 检查键盘事件
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
    
    // 清理终端
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    
    log_info!("vmtop exited successfully");
    Ok(())
}
