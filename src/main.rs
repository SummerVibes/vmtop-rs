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

// New struct to hold VM exit statistics
#[derive(Default, Clone)]
struct VmExitStats {
    exits: u64,
    halt_exits: u64,
    irq_exits: u64,
    kvm_msr_write: u64,
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

// 增强的collect_vmexit_stats函数，添加调试信息
fn collect_vmexit_stats(pid: Pid) -> VmExitStats {
    let debug_path = "/sys/kernel/debug/kvm";
    let mut stats = VmExitStats::default();
    
    log_debug!("Scanning KVM debug path for PID: {}", pid);
    
    if let Ok(entries) = fs::read_dir(debug_path) {
        for entry in entries.flatten() {
            if let Some(dir_name) = entry.file_name().to_str() {
                if dir_name.starts_with(&format!("{}-", pid)) {
                    
                    // 尝试读取各个统计文件
                    let exits_path = entry.path().join("exits");
                    let halt_exits_path = entry.path().join("halt_exits");
                    let irq_exits_path = entry.path().join("irq_exits");
                    let kvm_msr_write_path = entry.path().join("kvm_msr_write");
                    
                    // 读取exits
                    if let Ok(content) = fs::read_to_string(&exits_path) {
                        stats.exits = parse_exit_count(&content);
                    }
                    
                    // 读取halt_exits
                    if let Ok(content) = fs::read_to_string(&halt_exits_path) {
                        stats.halt_exits = parse_exit_count(&content);
                    }
                    
                    // 读取irq_exits
                    if let Ok(content) = fs::read_to_string(&irq_exits_path) {
                        stats.irq_exits = parse_exit_count(&content);
                    }
                    
                    // 读取kvm_msr_write
                    if let Ok(content) = fs::read_to_string(&kvm_msr_write_path) {
                        stats.kvm_msr_write = parse_exit_count(&content);
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
                    delta_stats.halt_exits = current_stats.halt_exits.saturating_sub(prev_stats.halt_exits);
                    delta_stats.irq_exits = current_stats.irq_exits.saturating_sub(prev_stats.irq_exits);
                    delta_stats.kvm_msr_write = current_stats.kvm_msr_write.saturating_sub(prev_stats.kvm_msr_write);
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
            
            // 创建表格数据
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
                    Cell::from(vm.exit_stats_delta.halt_exits.to_string()),
                    Cell::from(vm.exit_stats_delta.irq_exits.to_string()),
                    Cell::from(vm.exit_stats_delta.kvm_msr_write.to_string()),
                ]));
            }
            
            if vm_stats.is_empty() {
                rows.push(Row::new(vec![
                    Cell::from("-"),
                    Cell::from("No VMs found"),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("-"),
                ]));
            }
            
            let table = Table::new(rows)
                .header(Row::new(vec![
                    Cell::from("PID"),
                    Cell::from("UUID"),
                    Cell::from("User%"),
                    Cell::from("Kernel%"),
                    Cell::from("vCPU%"),
                    Cell::from("Memory(MB)"),
                    Cell::from("Exits"),
                    Cell::from("Halt"),
                    Cell::from("IRQ"),
                    Cell::from("MSR"),
                ]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
                .block(Block::default().title("vmtop - Virtual Machine Monitor").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(10),
                    Constraint::Length(36),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(12),
                    Constraint::Length(10),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                ]);
            
            f.render_widget(table, size);
        })?;
        
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
