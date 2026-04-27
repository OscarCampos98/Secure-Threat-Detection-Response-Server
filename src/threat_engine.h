#ifndef THREAT_ENGINE_H
#define THREAT_ENGINE_H

#include "parser.h"
#include <string>

using namespace std;
/*
    threat_engine.h

    Purpose:
    Declares the ThreatEngine class.

    The threat engine receives a ParsedMessage from the parser and
    classifies it into a threat level.

    Current milestone:
    - rule-based classification
    - no client history yet
    - no response engine yet

    Future:
    - repeated error detection
    - per-client scoring
    - client/session state tracking
    - configurable rules
*/

enum class ThreatLevel
{
    NORMAL,
    SUSPICIOUS,
    CRITICAL
};

/*
    Threat result stores the output of the threat engine

*/

struct ThreatResult
{
    ThreatLevel level;
    string reason;
};

class ThreatEngine
{
public:
    /*
    Analyzes a parsed message and returns treat classification
    */
    ThreatResult analyze(const ParsedMessage &message);

    // Converts ThreatLevel enum into readable text

    static string threatLevelToString(ThreatLevel level);
};

#endif
