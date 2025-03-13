# Network Packet Sniffer

## Description
This project is a **Network Packet Sniffer** written in C++ using the **PCAP** library. It captures network packets, analyzes IP headers, and extracts TCP/UDP details.

## Features
- Captures live network packets.
- Displays source and destination IP addresses.
- Identifies TCP and UDP packets along with their port numbers.
- Displays total packet length.
- Detects other protocols and lists them.

## Requirements
- **Linux** or **Windows with WSL**
- **libpcap** (Install with `sudo apt install libpcap-dev` on Linux)

## Installation
```bash
sudo apt update
sudo apt install libpcap-dev g++
```

## Compilation
```bash
g++ -o sniffer network_sniffer.cpp -lpcap
```

## Usage
```bash
sudo ./sniffer
```

## Notes
- Requires **root privileges** to capture packets.
- Select the correct network interface when prompted.
- Press `Ctrl + C` to stop sniffing.
