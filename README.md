# Threat Detection & Response Server

A modular multi-client backend server built in C++ for Linux environments, designed to receive client activity, detect suspicious behavior, classify threat levels, log security-relevant events, and support automated response workflows.

This project is the first major component of a larger Threat Detection & Response System that may later include lightweight client agents, a mission-control style dashboard, persistent storage, and deeper integration with secure telemetry infrastructure.

---

## Overview

Modern monitored systems—especially those involving **uncrewed platforms, distributed devices**, or Linux-based infrastructure—require continuous visibility into client activity, message behavior, and connection patterns.

This server acts as the **core detection and response layer**. It is responsible for:

- accepting connections from multiple clients
- processing client messages concurrently using a thread-per-client model
- parsing and validating incoming messages
- applying rule-based threat detection
- maintaining per-client threat state
- logging events, classifications, and response decisions
- triggering response actions based on severity

---

## Project Vision

The long-term vision is to build a small but realistic security monitoring system with three major parts:

1. **Client Agents** — lightweight programs that report activity from monitored machines
2. **Threat Detection Server** — the C++ backend that receives events, analyzes behavior, classifies threats, and triggers responses
3. **Mission Control Dashboard** — a live interface for viewing connected clients, alerts, logs, and threat state

The current repository begins with the Threat Detection Server, keeping the first implementation focused on backend networking, detection logic, client state tracking, and structured logging.

---

## Security Philosophy

This project approaches security from a **monitoring, detection, and response** perspective.
Rather than treating security as only encryption or authentication, the system focuses on:

- visibility into client and system behavior
- detection of abnormal or suspicious patterns
- classification of operational risk
- traceable logging of decisions and evidence
- controlled response actions based on severity

Secure communication, authentication, and stronger client identity validation are planned future improvements. The first goal is to build a clean detection and response foundation.

---
## Current Features
- Multi-client TCP server
- Thread-per-client connection handling
- Plain-text message parsing
- Rule-based threat classification
- Per-client state tracking
- Response decision engine
- File-based structured logging
- Connection-based client identity using IP and source Port

---

## Core Concepts

### Threat Detection
The server evaluates incoming messages using rule-based logic to identify suspicious or abnormal behavior.

Example rule categories include:

- repeated failed authentication attempts
- malformed messages
- unauthorized commands
- suspicious request frequency
- replayed request IDs
- invalid or expired session tokens
- repeated connection attempts from the same client
- unexpected message structure or invalid fields

---

### Per-Client State Classification

Each connected client maintains its own threat state:

- NORMAL
- SUSPICIOUS
- CRITICAL

State transitions are driven by message content, client behavior, connection patterns, and historical activity.

---

## Response Actions

Response refers to backend-driven actions based on threat severity.

Possible responses include:

- logging the event
- raising an alert
- marking a client/session as suspicious
- rejecting a request
- temporarily blocking a client
- increasing monitoring level for a client
- storing evidence in structured logs
  
---
## Example Message Format


The server currently supports both legacy plain-text messages and structured JSON messages.

Plain-text examples:

```text
HEARTBEAT
STATUS OK
ERROR TEMP_HIGH
COMMAND INVALID
```

JSON example:
```json
{
  "client_id": "sensor_01",
  "timestamp": "2026-04-30T09:40:00Z",
  "event_type": "AUTH_ATTEMPT",
  "status": "FAILED",
  "request_id": "abc123"
}
```

---
## Detection Scope

The system is designed to detect and respond to:

- malformed or invalid messages
- repeated error conditions
- repeated failed authentication attempts
- suspicious command patterns
- suspicious request frequency
- abnormal message frequency
- replayed request identifiers
- invalid or expired session tokens
- repeated connection attempts from the same client
- unusual client connection behavior
- suspicious IP-based activity patterns
- unauthorized or unknown client activity
- communication loss, such as missing heartbeats
- telemetry inconsistencies
- rule violations in expected message flow

---

## Project Structure

Initial server-focused structure:
```bash
threat-detection-server/
│
├── src/
│   ├── main.cpp
│   ├── server.cpp
│   ├── server.h
│   ├── parser.cpp
│   ├── parser.h
│   ├── threat_engine.cpp
│   ├── threat_engine.h
│   ├── response_engine.cpp
│   ├── response_engine.h
│   ├── client_state.cpp
│   ├── client_state.h
│   ├── logger.cpp
│   └── logger.h
│
├── logs/
│   └── threat_log.txt
│
├── docs/
│   └── architecture.md
│
├── tests/
│
├── Makefile
└── README.md
```
Long-term system structure may expand to include:

```bash
threat-detection-system/
│
├── server/      # C++ threat detection server
├── agent/       # future lightweight client agent
├── dashboard/   # future monitoring interface
├── docs/        # architecture notes, diagrams, threat rules
├── tests/       # test clients and detection tests
└── README.md
```

---

## Architecture
Current server architecture:


```bash
Multiple Clients
        ↓
TCP Listener (Server)
        ↓
Client Handler Threads
        ↓
Message Parser
        ↓
Threat Engine
        ↓
Client State Tracker
        ↓
Response Engine
        ↓
Logger
        ↓
Threat / Status Output
```
---

## Components

#### Server

- initializes TCP listener
- accepts multiple client connections
- spawns a thread per client
- receives incoming messages
- forwards client/message data into the processing pipeline

#### Message Parser
- validates incoming message format
- extracts message type and payload
- marks unknown or malformed messages as invalid
- forwards structured results to the threat engine

#### Threat Engine
- applies rule-based detection logic
- assigns threat level
- evaluates message content, client behavior, and recent activity

#### Client State Tracker
- tracks per-client connection history using IP and source Port
- stores recent events, failed attempts, suspicious behavior, and connection metadata
- supports client-specific threat classification

#### Response Engine
- decides what action to take based on threat level
- supports actions such as log, alert, reject, block, or increase monitoring level

#### Logger
- records timestamped events
- stores client identity, IP/connection metadata, message content, classification, and response decision

##### Example 
```text
[EVENT]
timestamp=2026-04-30 11:53:05
client_id=127.0.0.1:53854
client_ip=127.0.0.1
client_port=53854
raw_message={"client_id":"sensor_01","timestamp":"2026-04-30T09:40:10Z","event_type":"AUTH_ATTEMPT","status":"SUCCESS","request_id":"s1-003"}
message_type=AUTH_ATTEMPT
valid=true
is_json=true
message_client_id=sensor_01
message_timestamp=2026-04-30T09:40:10Z
event_type=AUTH_ATTEMPT
status=SUCCESS
request_id=s1-003
payload=SUCCESS
threat_level=NORMAL
threat_reason=Successful authentication attempt reported
client_state=NORMAL
total_events=3
normal_events=3
suspicious_events=0
critical_events=0
state_reason=Client remains normal

response_action=ALLOW
response_reason=No suspicious activity detected

[EVENT]
timestamp=2026-04-30 11:53:05
client_id=127.0.0.1:53856
client_ip=127.0.0.1
client_port=53856
raw_message={"client_id":"sensor_02","timestamp":"2026-04-30T09:40:10Z","event_type":"ERROR","status":"TEMP_HIGH","request_id":"s2-003"}
message_type=ERROR
valid=true
is_json=true
message_client_id=sensor_02
message_timestamp=2026-04-30T09:40:10Z
event_type=ERROR
status=TEMP_HIGH
request_id=s2-003
payload=TEMP_HIGH
threat_level=SUSPICIOUS
threat_reason=Error condition reported by client
client_state=SUSPICIOUS
total_events=3
normal_events=1
suspicious_events=2
critical_events=0
state_reason=Client marked suspicious

response_action=MONITOR
response_reason=Suspicious activity detected; increasing monitoring
```
For a bigger picture screenshot please see https://github.com/OscarCampos98/Threat-Detection-Response-Server/blob/main/Images/log_example_dash.png

#### Main
- orchestrates system flow
- initializes components
- manages lifecycle

--- 
## Architecture Diagram
![Diagram](Images/Current_diagramV1.0.png)



The diagram illustrate:
Note that AI was used to generate the diagram for now.

- multiple external clients
- TCP listener and connection handling
- thread-per-client execution model
- message parsing pipeline
- threat engine
- per-client state tracking
- response engine
- structured logging flow



## Use Cases

This system can conceptually apply to:

- monitoring client activity across Linux-based systems
- detecting suspicious command or authentication patterns
- analyzing event streams from distributed devices
- monitoring uncrewed vehicle telemetry channels
- supporting security monitoring pipelines
- acting as an analysis layer in a larger control or telemetry system

---
<!--
Development Roadmap
Phase 0: Setup & Foundation
set up Linux development environment
initialize Git repository
define project structure
create initial README and documentation notes
prepare Makefile/build workflow
Phase 1: Core Server
build a concurrent TCP server in C++
accept multiple client connections
implement thread-per-client handling
receive structured messages
parse and validate basic input
log received events
classify simple events as NORMAL or SUSPICIOUS
Phase 2: Threat Detection & Response
add multiple detection rules
implement client/session state tracking
support threat levels: NORMAL, SUSPICIOUS, and CRITICAL
add automated response decisions such as log, alert, reject, or block
improve structured logs and evidence trail
create repeatable test scenarios
Phase 3: Hardening & Polish
improve error handling
refine architecture and module boundaries
add scripted test clients
add sample logs and detection examples
document threat rules and response behavior
finalize architecture diagram
Phase 4: Persistence & Operations
add database-backed event storage, such as PostgreSQL
add log rotation or archival strategy
explore syslog or systemd integration
add queryable event history
Phase 5: Secure Communication & Client Identity
add encrypted message transport
add message integrity validation
add client authentication and identity validation
improve session handling and replay protection
Phase 6: System Expansion
develop lightweight client agents
add heartbeat monitoring from agents
add dashboard or terminal monitoring interface
integrate with secure telemetry systems
expand automated response workflows
---
-->



## Relationship to Other Systems

This project is designed to remain standalone during early development, while leaving room for future integration with a previously developed project:

**Secure Communication and Monitoring System**

That system focuses on secure telemetry transmission, encryption, PostgreSQL logging, and hardware-level monitoring on Raspberry Pi.

The **Threat Detection & Response Server** is intended to become a backend intelligence layer that can analyze incoming events and determine system risk levels before passing results to logging, alerting, dashboard, or telemetry components.

---

## Build and Run

Instructions will be added as implementation progresses.

Planned usage:

```bash
make
./threat_server
```
Testing example:
```bash 
nc localhost 8080
```
---
## Testing

The test scripts now include both plain-text and JSON event messages.

JSON tests validate:

- structured event parsing
- event type mapping
- logical client ID extraction
- request ID extraction
- JSON parse error handling
- classification of authentication events

### Manual Test Client

The manual client sends a predefined sequence of messages through a single TCP connection.
```bash 
python3 tests/manual_client.py
```

This test validates:

- normal message handling
- malformed input detection
- rule-based threat classification
- suspicious activity escalation
- response decision generation
- file-based logging

### Multi-Client Test

The multi-client test simulates multiple clients connecting to the server concurrently.
```bash
python3 tests/multi_client_test.py
```

This test validates:

- multiple client connections
- thread-per-client handling
- concurrent message processing
- logging under concurrent activity
- pipeline stability with multiple active clients

When running locally, simulated clients may share the same localhost IP address (127.0.0.1) while using different source ports. The current client state tracker uses IP address as the client identity, so local simulated clients may share the same tracked state.

More testing details are available in:

```text
docs/test_cases.md
```
---

## Status

Current baseline implementation completed:

- multi-client TCP server
- message parser
- threat engine
- per-client state tracker
- response decision engine
- file-based logger
- manual and multi-client test scripts

Next focus areas:

- improved client identity model
- JSON message support
- heartbeat timeout detection
- stronger automated testing

## Author

Oscar Campos
