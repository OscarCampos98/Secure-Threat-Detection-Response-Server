#include "logger.h"

#include <fstream>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

using namespace std;
/*
    logger.cpp

    Purpose:
    Implements file-based logging for the threat detection server.

    Current format:
    A structured plain-text log entry per event.

    Later improvements:
    - JSON logs
    - log rotation
    - syslog integration
    - database-backed event storage
*/

Logger::Logger(const string &log_file_path)
    : log_file_path(log_file_path) {}

string Logger::getCurrentTimestamp()
{
    /*
        Get the current system time.
    */
    auto now = chrono::system_clock::now();
    time_t current_time = chrono::system_clock::to_time_t(now);

    /*
        Convert the time into local time.

        localtime_r is used instead of localtime because localtime is not
        thread-safe. Since this server is multi-threaded, localtime_r is safer.
    */
    tm time_info;
    localtime_r(&current_time, &time_info);

    /*
        Format timestamp as:
        YYYY-MM-DD HH:MM:SS
    */
    ostringstream timestamp_stream;
    timestamp_stream << put_time(&time_info, "%Y-%m-%d %H:%M:%S");

    return timestamp_stream.str();
}

void Logger::logEvent(
    const string &client_ip,
    int client_port,
    const ParsedMessage &parsed_message,
    const ThreatResult &threat_result,
    const ClientStateUpdate &state_update,
    const ResponseDecision &response_decision)
{
    /*
        Lock before writing so multiple client threads do not write
        into the log file at the same time.
    */
    lock_guard<mutex> lock(log_mutex);

    /*
        Open file in append mode.
        This keeps previous logs and adds new entries at the end.
    */
    ofstream log_file(log_file_path, ios::app);

    if (!log_file.is_open())
    {
        cerr << "[ERROR] Failed to open log file: "
             << log_file_path << "\n";
        return;
    }

    /*
        Write one structured event record.
    */
    log_file << "[EVENT]\n";
    log_file << "timestamp=" << getCurrentTimestamp() << "\n";
    log_file << "client_ip=" << client_ip << "\n";
    log_file << "client_port=" << client_port << "\n";
    log_file << "raw_message=" << parsed_message.raw << "\n";
    log_file << "message_type="
             << Parser::messageTypeToString(parsed_message.type) << "\n";
    log_file << "valid=" << (parsed_message.valid ? "true" : "false") << "\n";

    if (!parsed_message.payload.empty())
    {
        log_file << "payload=" << parsed_message.payload << "\n";
    }

    if (!parsed_message.error.empty())
    {
        log_file << "parse_error=" << parsed_message.error << "\n";
    }

    log_file << "threat_level="
             << ThreatEngine::threatLevelToString(threat_result.level) << "\n";
    log_file << "threat_reason=" << threat_result.reason << "\n";
    log_file << "client_state="
             << ClientStateTracker::stateToString(state_update.current_state)
             << "\n";
    log_file << "total_events=" << state_update.total_events << "\n";
    log_file << "normal_events=" << state_update.normal_events << "\n";
    log_file << "suspicious_events=" << state_update.suspicious_events << "\n";
    log_file << "critical_events=" << state_update.critical_events << "\n";
    log_file << "state_reason=" << state_update.reason << "\n";
    log_file << "\n";
    log_file << "response_action="
             << ResponseEngine::actionToString(response_decision.action) << "\n";
    log_file << "response_reason="
             << response_decision.reason << "\n";
}