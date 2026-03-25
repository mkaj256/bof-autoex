# BOF-autoex: Automated Buffer Overflow Exploit Generator

[Русская версия](README_RU.md) | [English](README.md)

> **ETHICAL DISCLAIMER**
>
> This tool is intended exclusively for educational purposes, CTF competitions, and authorized security testing with explicit permission. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have explicit written permission before testing any binary. Do not use this tool on systems you do not own or lack authorization to test.

## Description

Automated Buffer Overflow (BOF) exploit generator for 64-bit ELF binaries. This tool analyzes the target binary using GDB, calculates stack offsets, generates position-independent shellcode avoiding bad bytes, and constructs a ready-to-use payload and exploit launcher. Designed for educational use and CTF scenarios where protections (canaries, PIE, NX) are disabled.

## Features

- Shellcode generation supporting `write` (print string), `execve` (execute command), and `crash` (test vulnerability) types
- Automatic bad bytes avoidance (e.g., `\x00`, `\x0a`) using register-level techniques
- Address refinement via optional core-dump analysis for more reliable exploitation
- Automated GDB workflow to extract buffer addresses and RIP offsets without manual debugging
- Exploit launcher script (`exploit.sh`) with ASLR disabled via `setarch -R`
- Test mode to build standalone shellcode executables for isolated verification

## Educational Value

This project is designed to be transparent and study-friendly. By examining the code, you can learn:

- Stack layout and return address overwrite mechanics (`modules/get_data.py`)
- Shellcode construction and bad-byte avoidance strategies (`modules/generate_shellcode_submodules/`)
- GDB automation for dynamic binary analysis
- Payload structure: NOP sled + shellcode + return address (`modules/generate_payload.py`)
- Modular architecture patterns for security tools

All logic is implemented in pure Python with detailed comments. No external exploit frameworks are used—only standard library and common Unix utilities.

## Requirements

Ensure the following tools are installed and available in your `PATH`:

| Tool | Purpose | Install (Debian/Ubuntu) |
|------|---------|------------------------|
| Python 3.8+ | Main runtime | `sudo apt install python3` |
| GDB | Dynamic binary analysis | `sudo apt install gdb` |
| Binutils (`as`, `objcopy`) | Shellcode assembly | `sudo apt install binutils` |
| util-linux (`setarch`) | ASLR disabling | `sudo apt install util-linux` |

Full install command:
```bash
sudo apt update && sudo apt install python3 gdb binutils util-linux
```

## Installation

Just clone the repository:
```bash
git clone https://github.com/mkaj256/bof-autoex.git
cd bof-autoex
```

## Usage

### Basic Example (Execve Shellcode)
Generate an exploit that executes `/bin/sh`:
```bash
python3 main.py ./vulnerable_binary -s execve -d "/bin/sh" -o output/
```

### Print a String (Write Shellcode)
Generate an exploit that prints "Hello World":
```bash
python3 main.py ./vulnerable_binary -s write -d "Hello World" -o output/
```

### Crash Program
Generate a minimal payload to trigger a segmentation fault:
```bash
python3 main.py ./vulnerable_binary -s crash -o output/
```

### Test Shellcode Independently
Build a standalone executable to verify shellcode behavior:
```bash
python3 main.py ./vulnerable_binary -s execve -d "/bin/sh" --test-shellcode
```

### Arguments Reference

| Argument | Description | Default |
| :--- | :--- | :--- |
| `binary` | Path to the vulnerable 64-bit ELF binary | *(required)* |
| `-s, --shellcode` | Shellcode type: `write`, `execve`, `crash` | `execve` |
| `-d, --data` | Data for shellcode (string/command) | *(required for write/execve)* |
| `-o, --output-dir` | Output directory for generated files | `./output` |
| `-v, --verbose` | Enable debug logging to stderr | `False` |
| `--test-shellcode` | Build standalone test binary instead of exploit | `False` |

## Contributing

Constructive criticism and suggestions are welcome. I am still learning, and this project is part of my educational journey. If you see something that can be improved — code clarity, documentation, or functionality — feel free to open an issue or submit a pull request.
