#ifndef CLIENT_STATE_H
#define CLIENT_STATE_H

#include "threat_engine.h"
#include "parser.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

using namespace std;

/*
    client_state.h

    Purpose:
    Declares the ClientStateTracker module.

    This module tracks behavior per client.

    Current client identity:
    - IP address

    Why IP address?
    - It works immediately with socket-based connections.
    - It supports early home-network testing.
    - Later, this can be replaced or extended with authenticated client IDs.

    Thread safety:
    - The server uses one thread per client.
    - Multiple threads may update client state at the same time.
    - A mutex protects the shared client state map.
*/
enum class ClientThreatState
{
    NORMAL,
    SUSPICIOUS,
    CRITICAL
};

// Stores historical activity for one client

struct ClientStats
{
    int total_envents = 0;
    int normal_events = 0;
    int suspicious_events = 0;
    int critical_events = 0;

    // Tracks failed authentications attemps, for this connection
    int failed_auth_attempts = 0;

    // Track id request
    unordered_set<string> seen_request_ids;

    ClientThreatState current_state = ClientThreatState::NORMAL;
};

/*
    returned after updating a client's state.
    letting the server print or log the updated client state.
*/

struct ClientStateUpdate
{
    string client_id;
    ClientThreatState current_state;

    int total_events;
    int normal_events;
    int suspicious_events;
    int critical_events;

    string reason;
};

class ClientStateTracker
{
private:
    unordered_map<string, ClientStats> clients;
    mutex state_mutex;

public:
    /*

    Update the stored state for a client based on the latex threat result

    client_id:
        currently the client's IP addres
    threat:
        results return by threat engine

    */
    ClientStateUpdate updateClientState(
        const string &client_id,
        const ThreatResult &threat,
        const ParsedMessage &parsed_message

    );

    // Converts ClientThreatState into readable text

    static string stateToString(ClientThreatState state);
};

#endif
