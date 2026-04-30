#ifndef LOGGER_H
#define LOGGER_H

#include "parser.h"
#include "threat_engine.h"
#include "client_state.h"
#include "response_engine.h"

#include <string>
#include <mutex>

using namespace std;

/*
    logger.h

    Purpose:
    Declares the Logger class.

    The logger is responsible for writing server events to a file.

    Current log target:
    - logs/threat_log.txt

    Thread safety:
    - The server uses one thread per client.
    - Multiple clients may try to write logs at the same time.
    - A mutex is used to prevent log lines from being mixed together.
*/

class Logger
{
private:
    string log_file_path;
    mutex log_mutex;

    /*
        Generate a readable timestamp for each log entry.
    */

    string getCurrentTimestamp();

public:
    // Constructor receives the target log file path
    explicit Logger(const string &log_file_path);

    // Writes one complete event record to the log file
    void logEvent(
        const string &connection_id,
        const string &client_ip,
        int client_port,
        const ParsedMessage &parsed_message,
        const ThreatResult &threat_result,
        const ClientStateUpdate &state_update,
        const ResponseDecision &response_decision

    );
};

#endif