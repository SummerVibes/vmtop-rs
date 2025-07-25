# vmtop-rs

A top-like tool for monitoring QEMU virtual machines

## Features
- Real-time monitoring of QEMU VMs
- Displays vCPU usage and memory consumption
- Top-like interface with sortable columns
- Configurable refresh interval

## Building Static Binaries

To build a statically linked binary:

1. Install musl tools:
```bash
sudo apt-get install musl-tools
```

2. Add musl target:
```bash
rustup target add x86_64-unknown-linux-musl
```

3. Build with musl target:
```bash
cargo build --release --target x86_64-unknown-linux-musl
```

The static binary will be at:
`target/x86_64-unknown-linux-musl/release/vmtop-rs`

## Usage
```bash
./vmtop-rs [OPTIONS]

Options:
  -i, --interval <INTERVAL>  Refresh interval in milliseconds [default: 1000]
  -h, --help                 Print help
  -V, --version              Print version
```

Press 'q' to exit the application.