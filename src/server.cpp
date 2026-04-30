#include "server.h"
#include "parser.h"
#include "threat_engine.h"
#include "client_state.h"

#include <iostream>
#include <cstring>
#include <thread>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

/*
    server.cpp

    Purpose:
    Implements the basic TCP server setup

    Current milestone:
    - create socket
    - bind socket to a port
    - listen for client connections
    - accept one connection
    - close connection cleanly

    Later:
    - each accepted client will be handled by a separate thread
    - messages will be passed into parser/threat engine/logger modules

*/

Server::Server(int port)
    : port(port),
      server_fd(-1),
      running(false),
      logger("logs/threat_log.txt") {}

bool Server::start()
{

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        cerr << "[ERROR] Failed to create socket\n";
        return false;
    }

    /*
        Allow quick server restart without waiting for a port
    */

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        cerr << "[ERROR] Failed to set socket options\n";
        close(server_fd);
        return false;
    }

    // Define the server address
    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(port);

    // Bind the socket
    if (bind(server_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0)
    {
        cerr << "[ERROR] Failed to bind socket to port " << port << "\n";
        close(server_fd);
        return false;
    }

    // Listen for incoming connections (10 is the backlog size)
    if (listen(server_fd, 10) < 0)
    {
        cerr << "[ERROR] Failed to listen on socket\n";
        close(server_fd);
        return false;
    }

    running = true;

    cout << "[INFO] Threat Detection Server started.\n";
    cout << "[INFO] Listening on port " << port << "...\n";

    /*
    Main accept loop.

    The server keeps accepting client connections until stop().
    Each client is handle in its own detached thread
    */

    while (running)
    {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, reinterpret_cast<sockaddr *>(&client_addr), &client_len);

        if (client_fd < 0)
        {

            // If the server is still soppused to be running,
            // This is an actual accept error.

            if (running)
            {
                cerr << "[ERROR] Failed to accept client connection\n";
            }
            continue;
        }

        /*
        Convert the client's IP address to a human-readable format
        */
        char client_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        int client_port = ntohs(client_addr.sin_port);

        cout << "[INFO] Client connected from "
             << client_ip << ":" << client_port << "\n";

        /*
        Start a new thread to handle the client connection

        important:
        client_ip is copied into a std::string because the local
        characters array will go out of the scope of the loop repeats

        */
        string client_ip_str(client_ip);
        thread client_thread(
            &Server::handleClient,
            this,
            client_fd,
            client_ip_str,
            client_port);

        /*
        Detach means the trhread runs independently

        Later, we may store threads and join them cleanly,
        but detach is acceptable for now
        */
        client_thread.detach();
    }

    return true;
}

void Server::handleClient(int client_fd, string client_ip, int client_port)
{
    // buffer to hold incoming data from the client
    // 1024 bytes should be sufficient for now
    // Connection-based client identifier.

    char buffer[1024];
    string connection_id = client_ip + ":" + to_string(client_port);
    Parser parser;
    ThreatEngine threat_engine;

    while (true)
    {
        /*
        clear the buffer before receiving new data
        */

        memset(buffer, 0, sizeof(buffer));

        /*
           recv() waits for data from the client.

           Return values:
           > 0  -> bytes received
           0    -> client disconnected
           < 0  -> receive error
       */

        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0)
        {
            string raw_message(buffer, bytes_received);
            ParsedMessage parsed = parser.parse(raw_message);
            ThreatResult result = threat_engine.analyze(parsed);

            ClientStateUpdate state_update = client_state_tracker.updateClientState(connection_id, result);

            ResponseDecision response = response_engine.decideResponse(result, state_update);

            logger.logEvent(
                connection_id,
                client_ip,
                client_port,
                parsed,
                result,
                state_update,
                response);

            cout << "[MESSAGE] "
                 << client_ip << " : " << client_port
                 << " -> " << parsed.raw << "\n";

            cout << "[PARSED] Type: "
                 << Parser::messageTypeToString(parsed.type)
                 << " | Valid: " << (parsed.valid ? "true" : "false");

            if (!parsed.payload.empty())
            {
                cout << " | Payload: " << parsed.payload;
            }

            if (!parsed.error.empty())
            {
                cout << " | Error: " << parsed.error;
            }

            cout << "\n";

            cout << "[THREAT] Level: "
                 << ThreatEngine::threatLevelToString(result.level)
                 << " | Reason: " << result.reason << "\n";

            cout << "[STATE] Client: "
                 << state_update.client_id
                 << " | State: "
                 << ClientStateTracker::stateToString(state_update.current_state)
                 << " | Events: " << state_update.total_events
                 << " | Normal: " << state_update.normal_events
                 << " | Suspicious: " << state_update.suspicious_events
                 << " | Critical: " << state_update.critical_events
                 << " | Reason: " << state_update.reason
                 << "\n";

            cout << "[RESPONSE] Action: "
                 << ResponseEngine::actionToString(response.action)
                 << " | Reason: " << response.reason << "\n";
        }

        else if (bytes_received == 0)
        {
            cout << "[INFO] Client disconnected: " << client_ip << ":" << client_port << "\n";
            break;
        }
        else
        {
            cerr << "[ERROR] Failed to receive data from client: " << client_ip << ":" << client_port << "\n";
            break;
        }
    }
    /*
    Close the client socket after communication is done
    */
    close(client_fd);
    cout << "[INFO] Closed connection with client: " << client_ip << ":" << client_port << "\n";
}

void Server::stop()
{
    // Close the server socket if open
    if (server_fd >= 0)
    {
        close(server_fd);
        server_fd = -1;
    }
    running = false;
    cout << "[INFO] Threat Detection Server stopped.\n";
}