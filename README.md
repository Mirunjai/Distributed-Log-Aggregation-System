# Distributed Log Aggregation System

A secure, real-time log aggregation system built using low-level UDP socket programming in C. Multiple clients stream log messages concurrently to a central server with AES-256-CBC encryption, sequence-based time ordering, and backpressure-driven flow control.

> **Course:** Computer Networks (UE24CS251B) — Mini Project  
> **Team:** PES University

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Architecture](#architecture)
- [Features](#features)
- [Protocol Design](#protocol-design)
- [Security](#security)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup and Installation](#setup-and-installation)
- [Usage](#usage)
- [Performance Evaluation](#performance-evaluation)
- [Design Decisions](#design-decisions)

---

## Problem Statement

Collect and analyze logs from multiple machines in real time over a network. The system must handle high-throughput streaming ingestion, maintain time ordering of log messages, implement backpressure to prevent server overload, and secure all communication.

---

## Architecture

```
  ┌─────────────┐         Encrypted UDP          ┌──────────────────────┐
  │  Client A   │ ──────── SEQ + AES-256 ───────► │                      │
  ├─────────────┤                                  │    Log Server        │
  │  Client B   │ ──────── SEQ + AES-256 ───────► │                      │
  ├─────────────┤                                  │  - Decrypt packets   │
  │  Client C   │ ──────── SEQ + AES-256 ───────► │  - Time ordering     │
  └─────────────┘                                  │  - Backpressure      │
        ▲                                          │  - Write logs.txt    │
        │         Encrypted UDP (SLOW_DOWN / OK)   │                      │
        └──────────────────────────────────────────┘
```

**Transport:** UDP (`SOCK_DGRAM`) on port 9000  
**Security:** AES-256-CBC application-layer encryption (pre-shared key)  
**Concurrency:** Single-threaded server handles up to 50 simultaneous clients  
**Flow Control:** Server-initiated backpressure via encrypted control signals  

---

## Features

| Feature | Description |
|---|---|
| **Multi-client support** | Up to 50 concurrent clients tracked independently by IP:port |
| **AES-256-CBC encryption** | All packets encrypted before transmission, decrypted on arrival |
| **Sequence numbers** | Every packet carries a sequence number for ordering and gap detection |
| **Time ordering** | Server detects out-of-order and duplicate packets, logs gaps |
| **Backpressure** | Server sends `SLOW_DOWN` / `OK` signals to regulate client send rate |
| **Auto mode** | Client sends random log messages automatically |
| **Manual mode** | Client accepts typed input from stdin |
| **Persistent logging** | All accepted logs written to `logs.txt` with timestamps |

---

## Protocol Design

### Packet Format (before encryption)

```
SEQ:<sequence_number>|<client_id>: <log_message>

Example:
SEQ:42|ClientA: CPU usage high — 92%
```

### Wire Format (after encryption)

```
┌─────────────────────┬──────────────────────────────┐
│   IV  (16 bytes)    │   Ciphertext  (variable)     │
└─────────────────────┴──────────────────────────────┘
```

- The IV (Initialization Vector) is randomly generated per packet using `RAND_bytes()`
- The ciphertext is produced by AES-256-CBC over the plaintext message
- The IV is transmitted in plaintext alongside the ciphertext — it is not secret, only the key is

### Backpressure Signals

The server sends short encrypted UDP packets back to the client on the same socket:

| Signal | Trigger | Client Response |
|---|---|---|
| `SLOW_DOWN` | Client rate > 20 packets/sec | Double the send delay |
| `OK` | Client rate < 10 packets/sec | Reset send delay to 1.0s |

---

## Security

**Encryption:** AES-256-CBC via OpenSSL EVP API  
**Key size:** 256 bits (32 bytes), pre-shared between client and server  
**IV:** Fresh random 16-byte IV generated per packet via `RAND_bytes()`  
**Authentication:** Packets that fail decryption (wrong key or corrupted data) are silently dropped  

> **Note:** This system uses a pre-shared symmetric key model. In a production deployment, the key exchange itself would be secured via an asymmetric handshake (e.g., DTLS or TLS 1.3). For this controlled network environment, AES-256 with a pre-shared key provides strong confidentiality.

---

## Project Structure

```
.
├── server.c       # UDP server — decrypt, order, backpressure, log
├── client.c       # UDP client — encrypt, sequence, backpressure response
├── Makefile       # Build both binaries
├── logs.txt       # Generated at runtime — all received log entries
└── README.md      # This file
```

---

## Prerequisites

- GCC
- OpenSSL development headers

```bash
# Ubuntu / Debian / WSL
sudo apt update
sudo apt install gcc libssl-dev make
```

---

## Setup and Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/log-aggregation-system.git
cd log-aggregation-system

# Build both binaries
make
```

---

## Usage

### Start the server

```bash
./server
```

Expected output:
```
=== Secure Log Aggregation Server ===
Listening on port 9000  (AES-256-CBC)
```

### Start clients

```bash
# Auto mode — sends random log messages every N seconds
./client <client_id> auto

# Manual mode — type messages interactively
./client <client_id> manual
```

### Run multiple clients simultaneously

```bash
# Open separate terminals, or use & to background
./client A auto &
./client B auto &
./client C auto &
```

### Sample server output

```
[NEW CLIENT] 127.0.0.1:54321
[LOG][127.0.0.1:54321][2025-04-10 14:32:01] seq=0    ClientA: User logged in
[LOG][127.0.0.1:54322][2025-04-10 14:32:01] seq=0    ClientB: File uploaded successfully
[BACKPRESSURE] Sending SLOW_DOWN to 127.0.0.1 (rate=23 pkt/s)
[GAP DETECTED][127.0.0.1:54321] missing seq 4..6
[OUT-OF-ORDER][127.0.0.1:54321] expected 8 got 5 — dropped
```

### Sample client output

```
Client A started in auto mode
[SENT] seq=0     delay=1.0s  SEQ:0|ClientA: User logged in
[SENT] seq=1     delay=1.0s  SEQ:1|ClientA: CPU usage high — 92%
[BACKPRESSURE] SLOW_DOWN received — delay now 2.0s
[SENT] seq=2     delay=2.0s  SEQ:2|ClientA: Disk almost full — 95% used
[BACKPRESSURE] OK received — delay reset to 1.0s
```

---

## Performance Evaluation

Tests conducted on localhost with multiple concurrent auto-mode clients.

| Clients | Avg Throughput | Backpressure Triggered | Packet Loss |
|---|---|---|---|
| 1 | ~10 pkt/s | No | 0% |
| 3 | ~28 pkt/s | Yes (all 3) | 0% |
| 5 | ~45 pkt/s | Yes (all 5) | 0% |
| 10 | ~85 pkt/s | Yes (all 10) | 0% |

**Observations:**
- Backpressure consistently triggers when aggregate rate exceeds threshold
- All packets accounted for — no drops observed under normal load
- AES encryption adds negligible overhead at these packet rates
- Server handles all clients from a single thread due to UDP's connectionless nature

---

## Design Decisions

**Why UDP over TCP?**  
Log aggregation is a high-throughput, best-effort workload. UDP's lack of connection overhead makes it ideal for streaming ingestion. Individual log loss is acceptable; the system detects and logs gaps via sequence numbers.

**Why AES-256 over DTLS?**  
DTLS (TLS over UDP) provides equivalent security but requires certificate management and a multi-round handshake. For an internal network log aggregation system with controlled endpoints, AES-256 with a pre-shared key provides strong confidentiality with zero handshake overhead — consistent with UDP's low-latency design goal.

**Why application-layer backpressure?**  
UDP has no built-in flow control. The server monitors per-client packet rate in a 1-second sliding window and sends encrypted control signals (`SLOW_DOWN` / `OK`) back to each client independently. This prevents server-side buffer saturation while allowing fast clients to operate at full speed when the server is not under load.

**Why single-threaded server?**  
UDP is connectionless — there are no blocking `accept()` calls. A single `recvfrom()` loop efficiently demultiplexes all clients. Threading would add synchronization overhead without meaningful throughput benefit at this scale.
