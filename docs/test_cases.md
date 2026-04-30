# Test Cases

This document describes the current manual and scripted test scenarios for the Threat Detection & Response Server.

The current testing approach validates the server pipeline:

```text
Client
  → TCP Server
  → Message Parser
  → Threat Engine
  → Client State Tracker
  → Response Engine
  → Logger
  ```

The tests are currently focused on verifying server behavior, message handling, threat classification, per-client state tracking, response decisions, and file-based logging.
---

# Prerequisites

Build the server from the project root:
```bash
make clean
make
```

Start the server:
```bash
./threat_server
```

The server should start and listen on port 8080:

```text
[INFO] Threat Detection Server started.
[INFO] Listening on port 8080...
```
---
# Test Script: Manual Client

File:
```text
tests/manual_client.py
```
Purpose:

The manual client sends a predefined sequence of messages to the server through a single TCP connection.

Run:
```bash
python3 tests/manual_client.py
```
```text
Messages Sent
HEARTBEAT
STATUS OK
ERROR TEMP_HIGH
ERROR TEMP_HIGH
ERROR TEMP_HIGH
COMMAND INVALID
BADMESSAGE
STATUS
ERROR
```

# Expected Behavior
```text
Message 	    Expected Parse Result	Threat Level	Expected Response

HEARTBEAT	    valid heartbeat	        NORMAL	        ALLOW

STATUS OK	    valid status	        NORMAL	        ALLOW
ERROR TEMP_HIGH	valid error	            SUSPICIOUS	    MONITOR

third repeated  valid error	            SUSPICIOUS	    BLOCK_CANDIDATE
ERROR TEMP_HIGH                                         after escalation

COMMAND INVALID	valid command	        CRITICAL	    BLOCK_CANDIDATE

BADMESSAGE	    unknown message     	CRITICAL	    BLOCK_CANDIDATE

STATUS	        missing payload	        CRITICAL	    BLOCK_CANDIDATE

ERROR	        missing payload	        CRITICAL	    BLOCK_CANDIDATE
```
---

# What This Test Validates
- TCP client connection handling
- plain-text message receiving
- message parsing
- malformed input detection
- rule-based threat classification
- suspicious activity escalation
- response decision generation
- structured file logging


---
# Test Script: Multi-Client Simulation


File:
```text
tests/multi_client_test.py
```
Purpose:

The multi-client test simulates several clients connecting to the server at the same time. Each simulated client runs in its own Python thread and sends a different message sequence.

Run:
```bash
python3 tests/multi_client_test.py
```

# Example Client Scenarios
```text
client_normal:
  HEARTBEAT
  STATUS OK
  HEARTBEAT

client_suspicious:
  HEARTBEAT
  ERROR TEMP_HIGH
  ERROR TEMP_HIGH

client_critical:
  COMMAND INVALID
  BADMESSAGE
  STATUS
```

#Expected Behavior

The server should:

- accept multiple connections
- sign each connection a different source port
- process messages from multiple clients without crashing
- write all events to the log file
- continue applying parser, threat, state, response, and logging logic to each event

Example log identifiers:
```text
client_ip=127.0.0.1
client_port=46124

client_ip=127.0.0.1
client_port=46132

client_ip=127.0.0.1
client_port=46148
```

# Important Note About Localhost Testing

### Important Note About Localhost Testing

When running multiple simulated clients locally, all clients may share the same IP address:

```text
client_ip=127.0.0.1
```

However, each TCP connection receives a different source port:
```text
127.0.0.1:46124
127.0.0.1:46132
127.0.0.1:46148
```

The current implementation uses a connection-based client identifier:
```text
client_id = client_ip:client_port
```
This allows the server to track state separately for each active connection during local multi-client testing.
This is a practical early-stage identity model. Future versions may support explicit client IDs, session tokens, or authenticated client identity.



---

# Log Verification

After running either test script, inspect the log file:
```text
tail -n 120 logs/threat_log.txt
```

Each event should include:
```text
[EVENT]
timestamp=
client_id=
client_ip=
client_port=
raw_message=
message_type=
valid=
threat_level=
threat_reason=
client_state=
total_events=
normal_events=
suspicious_events=
critical_events=
state_reason=
response_action=
response_reason=
```

For messages with payloads, the log should also include:
```text
payload=
```
For malformed or unknown messages, the log should include:
```text
parse_error=
```
---

# Current Test Coverage

The current tests validate:

- server startup
- TCP socket listening
- client connection handling
- thread-per-client behavior
- raw message receiving
- message parsing
- valid and invalid input handling
- threat classification
- repeated suspicious activity escalation
- per-IP client state tracking
- response decision generation
- file-based structured logging

---
# Known Testing Limitations

The current tests do not yet validate:

- authenticated client identity
- separate state across multiple real IP addresses
- encrypted communication
- JSON message validation
- heartbeat timeout detection
- actual firewall blocking
- database persistence
- automated pass/fail assertions

These are planned for future development phases.
---
 
# Future Test Improvements

Planned improvements include:

- testing with multiple devices on the same home network
- adding explicit client_id support
- adding automated expected-output validation
- adding parser unit tests
- adding threat engine unit tests
- adding response engine unit tests
- adding JSON-based test cases
- adding stress tests with higher client counts