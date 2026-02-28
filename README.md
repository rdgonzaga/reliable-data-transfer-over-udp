# NSCOM01 MCO1: Reliable Data Transfer over UDP

This project implements an application-layer **reliable file transfer protocol over UDP** using **Stop-and-Wait ARQ**.

It supports:

- `GET` (download from server to client)
- `PUT` (upload from client to server)

The implementation is in Python and follows the protocol specification defined in:

- **`[NSCOM01] MCO1 RFC.pdf`** (RFC 6769, February 2026)

For complete details about the protocol, **check the RFC file for full details**.

## Repository Structure

```text
reliable-data-transfer-over-udp/
├── README.md
├── [NSCOM01] MCO1 RFC.pdf
└── src/
		├── protocol.py
		├── server.py
		├── client.py
		├── client_files/
		└── server_files/
```

### Main Files

- `src/protocol.py`  
  Packet encoding/decoding, message constants, error constants, payload helpers.

- `src/server.py`  
  UDP server, session creation, GET/PUT handlers, Stop-and-Wait send/receive loops, teardown, and optional packet-loss simulation.

- `src/client.py`  
  Interactive UDP client shell with `get`, `put`, `help`, `quit`; handshake + transfer logic.

## How to Run

> Recommended: run both programs from the `src/` directory so relative folders (`client_files`, `server_files`) resolve as expected.

### 1) Start the server

From project root:

```bash
cd src
python server.py
```

Server startup prompts:

- Bind mode: localhost (`127.0.0.1`) or LAN (`0.0.0.0`)
- Verbose logging on/off
- Reliability test mode on/off (simulated loss + configurable loss rate)

Default server port in code: **`8080`**.

### 2) Start the client

Open another terminal:

```bash
cd src
python client.py
```

Enter server IP and port, then use:

- `get <filename> [chunk]`
- `put <filename> [chunk]`
- `help`
- `quit`

Examples:

```bash
get testget.txt
put ilovenscom.txt
get ilovedocmarnel.txt 512
put testget.txt 1024
```

## File Location Rules

- Files available for **download (GET)** must be in `src/server_files/`.
- Files to **upload (PUT)** must be in `src/client_files/`.
- Downloaded files are written to `src/client_files/`.
- Uploaded files are written to `src/server_files/`.

The implementation sanitizes incoming filenames on the server using `basename` semantics.

## Reliability Test Mode

`server.py` includes optional ACK/DATA drop simulation for testing retransmission behavior:

- `SIMULATE_LOSS`
- `LOSS_RATE`

When enabled during startup, the server intentionally drops some packets/ACKs to exercise timeout/retry paths.

## Authors

Developed by **[Lance Chiu](https://github.com/xmdbro)** and **[Rainer Gonzaga](https://www.github.com/rdgonzaga)**
