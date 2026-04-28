#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

#include "threat_engine.h"
#include "client_state.h"

#include <string>

using namespace std;

/*
    response_engine.h

    Purpose:
    Declares the ResponseEngine class.

    The response engine decides what action should be taken after
    a message is parsed, classified, and applied to client state.

    Current version:
    - decision-only response actions
    - no actual firewall blocking
    - no client disconnection yet
    - no external alerts yet

    Future:
    - disconnect critical clients
    - write block candidates
    - send alerts
    - integrate with system-level response tools
*/

enum class ResponseAction
{
    ALLOW,
    MONITOR,
    ALERT,
    REJECT,
    BLOCK_CANDIDATE
};

// ResponseDecision stored the respond action and reason
struct ResponseDecision
{
    ResponseAction action;
    string reason;
};

class ResponseEngine
{
public:
    /*
        Decides what response action should be taken base on:
        - latest threat classification
        - current per-cleint state
    */
    ResponseDecision decideResponse(
        const ThreatResult &threat_result,
        const ClientStateUpdate &state_update);

    // Convert ResponseAction enum into readable text.
    static string actionToString(ResponseAction action);
};

#endif