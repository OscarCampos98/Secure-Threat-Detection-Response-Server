# Threat Detection & Response Server Architecture

## Overview

The Threat Detection & Response Server is a Linux-based C++ backend system designed to receive client activity over TCP, parse incoming messages, classify threat levels, track client behavior over time, decide response actions, and write structured logs.

The current implementation focuses on the core backend pipeline. It supports multiple client connections using a thread-per-client model and maintains threat state for each client based on IP address.

---

## Current System Pipeline

```text
Client
  ↓
TCP Server
  ↓
Client Handler Thread
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
```
Each incoming message moves through this pipeline before the server prints status output and records an event log.
---

## Module Responsibilities

### Sever Core

File:
- src/server.h
- src/server.cpp

Responsibilities:

- create TCP socket
- bind to the configured port
- listen for incoming clients
- accept multiple connections
- spawn one thread per client
- receive messages from each connected client
- pass messages through the processing pipeline

### Message Parser
File:
- src/parser.h
- src/parser.cpp

Responsibilities:

- trim raw client input
- identify message type
- validate required payloads
- return a structured ParsedMessage

Current supported message types:
```text
HEARTBEAT
STATUS <payload>
ERROR <payload>
COMMAND <payload>
```
Malformed or unknown messages are marked invalid.

### Threat Engine
Files:
- src/threat_engine.h
- src/threat_engine.cpp

Responsibilities:

- analyze parsed messages
- apply rule-based detection logic
- assign a threat level
- provide a reason for the classification

Current threat levels:
```text
NORMAL
SUSPICIOUS
CRITICAL

```

Example rules:
```text
HEARTBEAT        → NORMAL
STATUS OK        → NORMAL
STATUS DEGRADED  → SUSPICIOUS
ERROR TEMP_HIGH  → SUSPICIOUS
COMMAND INVALID  → CRITICAL
BADMESSAGE       → CRITICAL

```
### Client State Tracker 
Files:
- src/client_state.h
- src/client_state.cpp

Responsibilities:

- track activity per client
- store event counters
- maintain each client's current state
- escalate repeated suspicious behavior

Current client identity:
```text
client IP address
```
Tracked Counters:
```text
total_events
normal_events
suspicious_events
critical_events
```

Current escalation rule:
```text
3 suspicious events from the same client → CRITICAL
```
### Response Engine

Files:

- src/response_engine.h
- src/response_engine.cpp

Responsibilities:

- decide what action should be taken after threat classification and state update
- return a response action and reason

Current response actions:
```text
ALLOW
MONITOR
ALERT
REJECT
BLOCK_CANDIDATE
```

Current behavior:
```text
NORMAL      → ALLOW
SUSPICIOUS  → MONITOR
CRITICAL    → BLOCK_CANDIDATE
```

The system does not currently enforce firewall blocking or disconnect clients automatically. It only produces response decisions.

### Logger

Files:

- src/logger.h
- src/logger.cpp

Responsibilities:

- write structured event logs
- include timestamp, client information, message details, threat level, client state, and response decision
- protect file writes with a mutex for thread safety

Current log path:
```text
logs/threat_log.txt
```

The log file is ignored by Git. Future sample logs should be stored under docs/ if needed.
---
## Threading Model

The server currently uses a thread-per-client model.
```text
Client A → Handler Thread A
Client B → Handler Thread B
Client C → Handler Thread C
```

Shared state, such as client state tracking and log writing, uses mutex protection where needed.
---

## Current Client Identity Model

The current implementation identifies clients using their IP address.

This is simple and useful for early LAN or Raspberry Pi testing.

Future improvements may include:

- explicit client IDs
- session tokens
- authenticated client identity
- replay protection
- stronger device identity validation
---

## Current Limitations

The current implementation does not yet include:

- encrypted communication
- authenticated clients
- real firewall blocking
- JSON message parsing
- persistent database storage
- heartbeat timeout detection
- dashboard or admin console

These are planned future improvements.
---

## Future Improvements

Planned development areas:

- structured JSON message format
- richer rule engine
- configurable detection rules
- heartbeat monitoring
- enforced response actions
- PostgreSQL event storage
- secure communication
- client authentication
- dashboard or terminal monitoring view
- Raspberry Pi telemetry integration