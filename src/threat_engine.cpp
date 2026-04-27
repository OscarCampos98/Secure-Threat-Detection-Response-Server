#include "threat_engine.h"

/*
    threat_engine.cpp

    Purpose:
    Implements rule-based threat classification.
 */

ThreatResult ThreatEngine::analyze(const ParsedMessage &message)
{
    // if the parser market the message invalid, treat it as critical
    // Reason: malforme or unknow input can indicate either broken client or suspecious activity

    if (!message.valid)
    {
        return {
            ThreatLevel::CRITICAL,
            "Invalid or unknown message format "};
    }

    // HeartBeat indicates the client is alive and communicating normally

    if (message.type == MessageType::HEARTBEAT)
    {
        return {
            ThreatLevel::NORMAL,
            "HeartBeat recieve"};
    }

    /*
        STATUS OK is normal,

        other STATUS payloads are suspecious for now becuase they may indicate degrade or abnormla client state
    */

    if (message.type == MessageType::STATUS)
    {
        if (message.payload == "OK")
        {
            return {
                ThreatLevel::NORMAL,
                "Status OK"};
        }
        return {
            ThreatLevel::SUSPICIOUS,
            "Non-OK Status reported"};
    }

    // ERROR messages indicates abnormal behavious or fault conditions
    if (message.type == MessageType::ERROR)
    {
        return {
            ThreatLevel::SUSPICIOUS,
            "Error condition reported by client"};
    }

    /*
        COMMAND INVALID is treated as critical because it represents
        an invalid or anauthorized command pattern
    */

    if (message.type == MessageType::COMMAND)
    {
        if (message.payload == "INVALID")
        {
            return {
                ThreatLevel::CRITICAL,
                "Invalid command detected"};
        }
        return {
            ThreatLevel::NORMAL,
            "Command message received"};
    }
    // Safety fallback
    return {
        ThreatLevel::CRITICAL,
        "Unhandle message type"};
}

string ThreatEngine::threatLevelToString(ThreatLevel level)
{
    switch (level)
    {
    case ThreatLevel::NORMAL:
        return "NORMAL";

    case ThreatLevel::SUSPICIOUS:
        return "SUSPICIOUS";

    case ThreatLevel::CRITICAL:
        return "CRITICAL";

    default:
        return "CRITICAl";
    }
}
