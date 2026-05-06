#!/usr/bin/env python3

"""
manual_client.py

Purpose:
    Scenario-based TCP test client for the Threat Detection & Response Server.

    This script connects to the local server, sends grouped test scenarios,
    and closes the connection after each scenario.

Why scenarios matter:
    The server tracks state per TCP connection. If all tests run through one
    connection, an early CRITICAL event affects every later test. Running each
    scenario in its own connection keeps test results easier to read.

Usage:
    1. Start the C++ server:
        ./threat_server

    2. In another terminal, run:
        python3 tests/manual_client.py
"""


import socket 
import time 

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080
MESSAGE_DELAY_SECONDS = 0.5
SCENARIO_DELAY_SECONDS = 1.0

def send_scenario(scenario_name, messages):
    """
    Opens one TCP connection, sends all messages for a scenario,
    then closes the connection.

    Each scenario gets a fresh connection so the server's connection-based
    state tracking does not mix unrelated test cases.
    """
    print("\n" + "=" * 70)
    print(f"[SCENARIO] {scenario_name}")
    print("=" * 70)

    print(f"[TEST CLIENT] Connecting to {SERVER_HOST}:{SERVER_PORT}")

    try:
        with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=5) as client_socket:
            print("[TEST CLIENT] Connected.")

            for message in messages:
                print(f"[TEST CLIENT] Sending: {message}")
                client_socket.sendall((message + "\n").encode("utf-8"))
                time.sleep(MESSAGE_DELAY_SECONDS)
            
            print(f"[TEST CLIENT] Finished scenario: {scenario_name}")
    except ConnectionRefusedError:
        print("[ERROR] Connection refused. Is the server running?" )
    except TimeoutError:
        print("[ERROR] Connection time out." )
    except OSError as error:
        print(f"[ERROR] Socket error: {error}" )
    
    print("[TEST CLIENT] Disconnected")
    time.sleep(SCENARIO_DELAY_SECONDS)

def test_normal_traffic():
    messages = [
        "HEARTBEAT",
        "STATUS OK",
        '{"client_id":"sensor_01","timestamp":"2026-04-29T18:30:00Z","event_type":"HEARTBEAT","status":"OK","request_id":"normal001"}',
        '{"client_id":"sensor_01","timestamp":"2026-04-29T18:30:05Z","event_type":"AUTH_ATTEMPT","status":"SUCCESS","request_id":"normal002"}',
    ]

    send_scenario("Normal traffic", messages)

def test_dns_query_detection():
    messages =[
        '{"client_id":"home_dns_monitor","timestamp":"2026-05-05T18:30:00Z","event_type":"DNS_QUERY","status":"OK","domain":"example.com","request_id":"dns001"}',
        '{"client_id":"home_dns_monitor","timestamp":"2026-05-05T18:30:05Z","event_type":"DNS_QUERY","status":"SUSPICIOUS_DOMAIN","domain":"fake-login-example.com","request_id":"dns002"}',
        '{"client_id":"home_dns_monitor","timestamp":"2026-05-05T18:30:10Z","event_type":"DNS_QUERY","status":"KNOWN_MALICIOUS_DOMAIN","domain":"malware-example.com","request_id":"dns003"}',
    ]

    send_scenario("DNS query detection", messages)

def test_replay_detection():
    messages =[
        # First replay001 should be normal.
        # Second replay001 should become suspicious as a possible retry or replay.
        '{"client_id":"sensor_01","timestamp":"2026-04-29T18:29:50Z","event_type":"HEARTBEAT","status":"OK","request_id":"replay001"}',
        '{"client_id":"sensor_01","timestamp":"2026-04-29T18:29:50Z","event_type":"HEARTBEAT","status":"OK","request_id":"replay001"}',
    ]

    send_scenario("Request ID replay detection", messages)

def test_failed_auth_treshold():
    messages =[
        # First and second failed auth attempts should be suspicious.
        # Third failed auth attempt should escalate the connection to critical.
        '{"client_id":"sensor_01","timestamp":"2026-04-29T18:31:00Z","event_type":"AUTH_ATTEMPT","status":"FAILED","request_id":"authfail001"}',
        '{"client_id":"sensor_01","timestamp":"2026-04-29T18:31:05Z","event_type":"AUTH_ATTEMPT","status":"FAILED","request_id":"authfail002"}',
        '{"client_id":"sensor_01","timestamp":"2026-04-29T18:31:10Z","event_type":"AUTH_ATTEMPT","status":"FAILED","request_id":"authfail003"}',
    ]

    send_scenario("Failed authentication threshold", messages)

def test_error_escalation():
    messages =[
        # Three suspicious ERROR events should escalate the connection to critical.
        "ERROR TEMP_HIGH",
        "ERROR TEMP_HIGH",
        "ERROR TEMP_HIGH",
    ]

    send_scenario("Repeat error escalation", messages)

def test_invalid_messages():
    messages = [
        "COMMAND INVALID",
        "BADMESSAGE",
        "STATUS",
        "ERROR",

        # Malformed JSON
        '{"client_id":"sensor_01","event_type":"AUTH_ATTEMPT","status":"FAILED"',
    ]

    send_scenario("Invalid and malformed messages", messages)

def main():
    print("[TEST CLIENT] Starting scenario-based manual tests")

    test_normal_traffic()
    test_dns_query_detection()
    test_replay_detection()
    test_failed_auth_treshold()
    test_error_escalation()
    test_invalid_messages()

    print("\n[TEST CLIENT] All manual test scenarios completed.")

if __name__ == "__main__":
    main()