# Uchenna_NAU_CYB-221_Assisgnment

Name: Odibendi Chukwuemelie Uchenna

Registration Number: 2024924004

Course Code: NAU-CYB 221

Level: 200l

Department: Cyber Security

Faculty: Physical Science



## Project Overview

This is a lightweight **C++ command-line tool** that reads Linux `/proc/net/tcp` and `/proc/net/udp` files to enumerate listening TCP ports and bound UDP sockets on the local machine.

It displays:

- Protocol (TCP/UDP)  
- Port number  
- Local bind address (e.g. 0.0.0.0, 127.0.0.1)  
- PID & process name (requires root privileges)  
- Service name (from `/etc/services`)  
- Risk classification (Local-only vs Exposed)  
- Security flag (High-Interest for sensitive/well-known ports)  
- TCP state (e.g. LISTEN, ESTABLISHED)

**Important:** This tool performs **local inspection only**. It does **not** scan remote hosts or perform any network probing.

## Features

- Parses `/proc/net/tcp` and `/proc/net/udp` directly  
- Converts hex IP/port format to human-readable values  
- Attempts inode → PID mapping to show owning process (root required)  
- Classifies ports as Local-only (127.0.0.1) or Exposed (0.0.0.0 / public IPs)  
- Flags well-known sensitive ports (21,22,23,25,53,80,110,139,143,443,445,3389,…)  
- Clean terminal table output with alignment  
- Basic error handling and root-privilege warning

## Requirements

- Linux system with `/proc` filesystem mounted (most distributions)  
- g++ compiler (C++11 or newer)  
- Run as **root** (or with `sudo`) to see process names / PIDs  
- Tested on: **ChromeOS Crostini** (Debian-based container)

## Build Instructions

```bash
# Compile (one-time)
g++ -o port_inspector port_inspector.cpp -std=c++11 -Wall

# Or with optimization
g++ -o port_inspector port_inspector.cpp -std=c++11 -O2 -Wall
