#include "response_engine.h"

/*
    response_engine.cpp

    Purpose:
    Implements response decision logic.

    Current behavior:
    - NORMAL events are allowed.
    - SUSPICIOUS events increase monitoring.
    - CRITICAL events generate alert/reject/block-candidate decisions.

    This module does not directly enforce network blocking yet.
    It only decides what should happen.
*/

ResponseDecision ResponseEngine::decideResponse(
    const ThreatResult &threat_result,
    const ClientStateUpdate &state_update)
{
    /*
        If the client is already in CRITICAL state, mark it as a block candidate.

        This can happen because:
        - a critical event was detected directly
        - repeated suspicious behavior escalated the client state
    */
    if (state_update.current_state == ClientThreatState::CRITICAL)
    {
        return {
            ResponseAction::BLOCK_CANDIDATE,
            "Client is in critical state and should be considered for blocking"};
    }

    /*
        Direct critical threat result should be rejected immediately.
    */
    if (threat_result.level == ThreatLevel::CRITICAL)
    {
        return {
            ResponseAction::REJECT,
            "Critical threat detected; request should be rejected"};
    }

    /*
        Suspicious events are not blocked immediately.
        They should be monitored and tracked.
    */
    if (threat_result.level == ThreatLevel::SUSPICIOUS)
    {
        return {
            ResponseAction::MONITOR,
            "Suspicious activity detected; increasing monitoring"};
    }

    /*
        Normal events are allowed.
    */
    return {
        ResponseAction::ALLOW,
        "No suspicious activity detected"};
}

std::string ResponseEngine::actionToString(ResponseAction action)
{
    switch (action)
    {
    case ResponseAction::ALLOW:
        return "ALLOW";

    case ResponseAction::MONITOR:
        return "MONITOR";

    case ResponseAction::ALERT:
        return "ALERT";

    case ResponseAction::REJECT:
        return "REJECT";

    case ResponseAction::BLOCK_CANDIDATE:
        return "BLOCK_CANDIDATE";

    default:
        return "UNKNOWN";
    }
}