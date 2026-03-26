# Threat Detection & Response Server

A modular **multi-client backend server** built in **C++ on Linux**, designed to monitor incoming system messages, detect suspicious behavior, maintain **per-client threat state**, and support structured response workflows in security-sensitive environments.

This project is developed as a **standalone prototype** with a long-term goal of integrating into a broader **secure telemetry and monitoring architecture**.

---

## Overview

Modern systems—especially those involving **uncrewed platforms** and **distributed devices**—require continuous monitoring to detect anomalies, faults, and potential security risks.

This server acts as a **central analysis component** that:

- accepts connections from **multiple clients**
- processes messages concurrently (thread-per-client model)
- analyzes message patterns and behavior
- classifies **per-client threat state**
- logs structured events for monitoring and investigation
- lays the foundation for future automated response workflows

---

## Project Vision

The long-term vision of this project is to build a backend system capable of:

- monitoring real-time activity across multiple clients
- detecting operational and security-related anomalies
- maintaining per-client and system-level threat awareness
- supporting alerting and response mechanisms
- integrating with external systems such as telemetry pipelines, logging infrastructure, and control systems

---

## Security Philosophy

This project approaches security from a **monitoring and detection perspective**.

Rather than focusing solely on secure communication (e.g., encryption or authentication), the system emphasizes:

- visibility into system behavior
- detection of abnormal or suspicious patterns
- classification of system risk levels
- support for informed response decisions

Security in this context is achieved through **awareness, analysis, and controlled response**, forming a foundation that can later be extended with secure communication and stronger protections.

---

## Core Concepts

### Threat Detection
The system evaluates incoming messages using rule-based logic (initially) to identify abnormal or suspicious behavior.

### Per-Client State Classification
Each connected client maintains its own threat state:

- `NORMAL`
- `SUSPICIOUS`
- `CRITICAL`

State transitions are driven by message patterns and detected anomalies.

### Response

Response refers to backend-driven actions such as:

- alert generation
- state escalation
- structured event logging
- signaling to connected systems (future)

The system is designed to evolve toward more active response capabilities over time.

---

## Example Message Types

```text
HEARTBEAT
STATUS OK
ERROR TEMP_HIGH
COMMAND INVALID
```
---
## Detection Scope (Planned)

The system is designed to evolve toward detecting:

- malformed or invalid messages
- repeated error conditions
- suspicious command patterns
- abnormal message frequency
- communication loss (e.g., missing heartbeat)
- unauthorized or unknown client activity
- unusual client connection behavior
- suspicious IP-based activity patterns
- telemetry inconsistencies
- rule violations in expected message flow

---
## Project Structure 
```bash
threat-detection-server/
│
├── src/
│   ├── main.cpp
│   ├── server.cpp
│   ├── server.h
│   ├── analyzer.cpp
│   ├── analyzer.h
│   ├── logger.cpp
│   └── logger.h
│
├── logs/
│   └── threat_log.txt
│
├── Makefile
└── README.md
```

---

## Architecture 
```bash 
Multiple Clients
        ↓
TCP Listener (Server)
        ↓
Client Handler Threads
        ↓
Analyzer
        ↓
Per-Client State Tracking
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
- forwards client/message data for analysis

#### Analyzer
- interprets messages
- applies detection logic
- tracks threat state per client
- determines client-level and system-level state transitions

#### Logger
- records events with timestamps
- stores client identity (IP/connection), message, classification, and state

#### Main
- orchestrates system flow
- initializes components
- manages lifecycle

## Architecture Diagram
![Diagram](Images/Threat_Detection_and_Response_Server.drawio)

A visual architecture diagram will be added here (planned using draw.io).

This diagram will represent the system at a component level and illustrate:

- multiple external clients
- TCP listener and connection handling
- thread-per-client execution model
- message flow into the analyzer
- per-client state tracking
- logging pipeline
- future response and telemetry integration points

## Use Cases

This system can conceptually apply to:

- monitoring uncrewed vehicle telemetry channels
- backend monitoring for distributed systems
- detecting anomalies in system command streams
- supporting security monitoring pipelines
- acting as an analysis layer in a larger control system

---

## Development Roadmap

### Phase 1: Core Detection Server
- concurrent TCP server for multiple clients
- thread-per-client connection handling
- plain-text message handling
- rule-based detection
- per-client threat-state classification
- file-based logging

### Phase 2: Enhanced Monitoring
- improved detection rules
- message pattern analysis
- heartbeat monitoring
- richer per-client state analysis
- structured log format improvements

### Phase 3: Data & Persistence
- database integration (e.g., PostgreSQL)
- persistent event storage
- queryable log system

### Phase 4: Secure Communication
- encrypted message transport
- message integrity validation
- client authentication and identity validation

### Phase 5: Response & Integration
- alerting mechanisms
- integration with telemetry systems
- automated response workflows


---

## Relationship to Other Systems

This project is designed to integrate with a previously developed system: Secure Communication and Monitoring System
That system focuses on secure telemetry transmission, encryption, and hardware-level monitoring. The Threat Detection & Response Server acts as a backend intelligence layer, responsible for analyzing incoming data and determining system risk levels.

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

## Status
Currently in early development.

Focus areas:

- backend server implementation
- concurrent message handling
- detection logic
- logging system
