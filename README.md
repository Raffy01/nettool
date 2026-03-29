# C Network Reconnaissance Utility (Nettool)
This repository provides a C-based, multithreaded network scanner and reconnaissance tool. By utilizing POSIX Raw sockets to directly manipulate IP, ICMP, and TCP headers, the utility bypasses standard operating system network layers. It supports high-speed asynchronous ICMP ping sweeps, stealth TCP SYN scans, network routing trace (Traceroute), and precise Operating System (OS) fingerprinting via TTL and TCP Window Size analysis.

---

## Repository Structure
```
.
├── Makefile
├── nettool.h
├── main.c
├── utils.c
├── ping.c
├── trace.c
└── scan.c
```

- **nettool.h** The core header file that defines shared global variables, macros, data structures (like the TCP pseudo-header), and function prototypes used across all modules.

- **main.c** The CLI entry point. It initializes global states, parses user command-line options using getopt_long, enforces root privilege requirements, and processes target strings (resolving domain names or calculating CIDR subnet ranges).

- **utils.c** Contains generalized network utility functions, including checksum calculation, hostname-to-IP resolution, local IP discovery, and the core OS fingerprinting logic based on IP/TCP headers.

- **ping.c** Implements ICMP Echo Request/Reply operations. Includes a standard ping tester with RTT statistics and a highly optimized, asynchronous Ping Sweep (-n) that can discover live hosts across an entire subnet in under 1.5 seconds.

- **trace.c** Implements Traceroute functionality by incrementally increasing the IP Time-To-Live (TTL) field to map network hops and measure transit delays to the destination.

- **scan.c** The multithreaded port scanning engine. Dispatches worker threads to perform standard TCP Connect scans (--st), UDP scans (--su), and custom-crafted TCP SYN stealth scans (--ss) that extract detailed OS fingerprints and banner strings without completing the 3-way handshake.

---
## Prerequisites

1. **Linux OS** (Requires POSIX system calls and Raw socket support, which are heavily restircted or differently implemented on Windows/macOS).
2. **GCC** (version >= 7.0).
3. **Pthread Library** (Required for multithreaded port scanning).
4. **Root Privileges** (Execution strictly requires `sudo` to open `SOCK_RAW` sockets).

---

## Installation & Setup
1. **Install dependencies** (Basic build tools):
    ```bash
    sudo apt update
    sudo apt install -y build-essential
    ```
2. **Clone or copy** this repository to your local machine.
3. **Compile the program**:
    ```bash
    make
    ```
    This will generate the executable binary: `nettool`.

    **Note**: When executed, the program automatically logs open ports and discovered hosts to `nettool_result.log` in the current directory. It intelligently transfers file ownership back to the invoking user (via `SUDO_UID` and `SUDO_GID`) to prevent root-lock on the log file.
4. **Clean build files** (optional):
    ```bash
    make clean
    ```

---

## Usage
The tool must be run with root privileges.
```bash
sudo ./nettool [OPTIONS] [TARGET IP/DOMAIN or CIDR]
```
**Targeting**:

- Supports single IP addresses (e.g., 192.168.0.1), Domain names (e.g., google.com), and CIDR subnet notations (e.g., 192.168.0.0/24).

**Mode Options**:

- `-s <PORT_RANGE>` : Perform a port scan on the specified range (e.g., `-s 80` or `-s   1-1024`).

    - `--st` : TCP Connect scan (Default. Highly reliable but leaves logs on the target).

    - `--ss` : TCP SYN stealth scan (Bypasses logs, highly concurrent, and performs OS fingerprinting).

    - `--su` : UDP port scan.

- `-n`, `--sn` : High-speed Ping Sweep. Discovers live hosts in a subnet without scanning ports.

- `-p` : Standard Ping mode.

    - `--infinite` : Ping continuously until manually stopped (Ctrl+C).

- `-t` : Traceroute mode. Maps network hops to the target.

**Tuning Options**:

- `-W <THREADS>` : Number of concurrent threads for port scanning (default: 50).

- `-T <MS>` : Timeout threshold for packet responses in milliseconds (default: 500).

- `-f <FILE>` : Read targets from a text file (one IP/domain per line).

---

## Example Workflow

1. **Discover live hosts in a local subnet**:
    ```bash
    sudo ./nettool -n 192.168.0.0/24
    ```
    Output:
    ```plaintext
    [안내] 고속 Ping Sweep 시작 (대상 호스트: 254개)...
    [Alive] 살아있는 호스트 발견: 192.168.0.1     [TTL:  64, OS: Linux/Unix/Mac]
    [Alive] 살아있는 호스트 발견: 192.168.0.5     [TTL: 128, OS: Windows]
    Sweep 완료! 총 2개의 호스트 발견.
    ```
2. **Perform a stealth SYN scan on a specific target with OS fingerprinting**:
    ```bash
    sudo ./nettool -s 1-1000 --ss -W 100 scanme.nmap.org
    ```
    Output:
    ```plaintext
    [scanme.nmap.org (45.33.32.156)] 멀티스레드 TCP(SYN) 포트 스캔 시작 (범위: 1-1000, 스레드: 100개)...
    [열림] 포트 22   /tcp - (응답 없음, 추측: ssh) [OS: Linux (커널 2.4~2.6+) | TTL:53, Win:29200]
    [열림] 포트 80   /tcp - (응답 없음, 추측: http) [OS: Linux (커널 2.4~2.6+) | TTL:53, Win:29200]
    스캔 완료! 총 2개의 포트 발견.
    ```

---

## Troubleshooting
- **"오류: 명령을 실행하려면 루트(sudo) 권한이 필요합니다."** : You must run the program with sudo. Raw sockets require root capabilities on Linux.

- **Scan defaults to Connect Scan instead of SYN Scan** : Ensure you are using double dashes for long options (`--ss`). Using `-ss` will be misinterpreted by the option parser.

- **Port unreachable/Host down but you know it's alive** : Increase the timeout threshold using `-T 1000` (1 second) if testing against targets on a high-latency WAN.

---

## Customization
- **Thread Count & Timeout**: If you frequently scan large networks, you can change the default `max_threads` (50) and `timeout_ms` (500) variables inside `main.c` to better fit your hardware and network environment.

- **Banner Grabbing Extension**: The current TCP scanning routine sends a basic `HEAD / HTTP/1.0` payload to probe for HTTP banners. You can easily extend this in `scan.c` to send custom probes for FTP, SMTP, or custom application protocols.

---

## License
This source code is licensed under the MIT License. See the `LICENSE` file for details.

---
_Last Updated: March 29, 2026_