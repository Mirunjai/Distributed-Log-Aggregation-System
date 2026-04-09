# Distributed Log Aggregation System

Collects and stores log messages from multiple machines in real time over a UDP socket connection. All messages are encrypted with AES-256-CBC before being sent.

---

## Project Details

| Item | Detail |
|---|---|
| Protocol | UDP (raw sockets) |
| Security | AES-256-CBC encryption |
| Language | C (server + client), Python (performance test) |
| Concurrency | Multiple clients supported simultaneously |

---

## System Architecture

```
[Client 1]  ─┐
[Client 2]  ──┼──(UDP + AES-256)──► [Server] ──► logs.txt
[Client N]  ─┘
```

Each client encrypts every log message with AES-256-CBC and sends it as a UDP datagram. The server decrypts, checks sequence numbers for ordering, logs to file, and sends backpressure signals when a client is sending too fast.

**Key features:**
- Time-ordered logging with sequence number tracking
- Gap detection (server warns when packets are missed)
- Backpressure: server sends `SLOW_DOWN` / `OK` signals to each client
- Up to 50 concurrent clients

---

## File Structure

```
├── server.c         — UDP server, decryption, logging, backpressure
├── client.c         — UDP client, encryption, auto/manual mode
├── perf_test.py     — Spawns N parallel clients, measures throughput & latency
├── Makefile         — Build script
└── README.md
```

---

## Setup and Build

**Requirements:**

```bash
# Ubuntu/Debian
sudo apt install gcc libssl-dev

# Python performance test only
pip install cryptography
```

**Build:**

```bash
make
```

This produces two binaries: `server` and `client`.

---

## Running

**Step 1 — Start the server:**

```bash
./server
```

Server listens on port 9000. Logs are saved to `logs.txt`.

**Step 2 — Start a client (auto mode):**

```bash
./client 1 auto
```

Sends random log messages automatically, one per second.

**Step 3 — Start more clients (in separate terminals):**

```bash
./client 2 auto
./client 3 auto
```

**Manual mode (type your own messages):**

```bash
./client 1 manual
```

---

## Performance Test

Run the server first, then:

```bash
# Default: 5 clients, 100 packets each
python3 perf_test.py

# Custom
python3 perf_test.py --clients 10 --packets 200 --server 127.0.0.1
```

**Sample output:**

```
============================================================
  Distributed Log Aggregation — Performance Test
============================================================
  Clients  : 5
  Packets  : 100 per client
  Total    : 500
  Server   : 127.0.0.1:9000
============================================================

Client     Sent       Time(s)    Avg lat(ms)      Min      Max
------------------------------------------------------------
  1         100         1.23          0.041    0.031    0.198
  2         100         1.24          0.039    0.029    0.187
  3         100         1.25          0.042    0.030    0.201
  4         100         1.23          0.040    0.028    0.195
  5         100         1.24          0.041    0.031    0.204
------------------------------------------------------------

  Total packets sent   : 500
  Wall-clock time      : 1.25 s
  Overall throughput   : 400.0 pkt/s

  Latency (all clients)
    Mean  : 0.041 ms
    Median: 0.040 ms
    Stdev : 0.008 ms
    Min   : 0.028 ms
    Max   : 0.204 ms
```

---

## Security

All data (log messages and control signals like `SLOW_DOWN`/`OK`) is encrypted with AES-256-CBC before being sent over the network. A random 16-byte IV is generated per packet and prepended to the ciphertext. The pre-shared key is 32 bytes and is identical in both `server.c` and `client.c`.

This satisfies the requirement for secure communication as an alternative to SSL/TLS.

---

## Backpressure

The server tracks how many packets each client sends per second:

| Rate | Action |
|---|---|
| > 20 packets/sec | Sends encrypted `SLOW_DOWN` to that client |
| < 10 packets/sec | Sends encrypted `OK` (client resets to normal speed) |

The client doubles its send delay on `SLOW_DOWN` and resets on `OK`.

---

## Error Handling

- Decryption failure → packet dropped, error printed, server keeps running
- Invalid packet format → dropped with a warning
- Out-of-order sequence → dropped and logged
- Sequence gap → server prints a warning noting the missing range
- Max clients (50) reached → new connections dropped gracefully

---

## Team

Project 21 — Socket Programming (Jackfruit Mini Project)
