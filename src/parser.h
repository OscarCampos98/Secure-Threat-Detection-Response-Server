#ifndef PARSER_H
#define PARSER_H

#include <string>

using namespace std;
/*
    parser.h

    Purpose:
    Declares the message parsing layer.

    The parser converts raw client input into a structured format
    that the threat engine can evaluate.

    Current support:
    - legacy plain-text messages
    - JSON messages

    Plain-text examples:
        HEARTBEAT
        STATUS OK
        ERROR TEMP_HIGH
        COMMAND INVALID

    JSON example:
        {
            "client_id": "sensor_01",
            "timestamp": "2026-04-23T18:30:00Z",
            "event_type": "AUTH_ATTEMPT",
            "status": "FAILED",
            "request_id": "abc123"
        }
*/

enum class MessageType
{
    HEARTBEAT,
    STATUS,
    ERROR,
    COMMAND,
    AUTH_ATTEMPT,
    DNS_QUERY,
    UNKNOWN,
    INVALID
};

struct ParsedMessage
{
    bool valid = false;

    /*
        Indicates whether the original message was JSON.
        This lets the logger and future modules understand
        how the message was received.
    */

    bool is_json = false;
    MessageType type = MessageType::INVALID;

    /*
        raw:
            cleaned original message

        payload:
            legacy/plain-text payload or useful JSON value
            such as status, command, or error code

        error:
            parser error reason when valid == false
    */
    string raw;
    string payload;
    string error;

    // JSON field

    string client_id;
    string timestamp;
    string event_type;
    string status;
    string request_id;
    string domain;
};

class Parser
{
public:
    /*
        Parses a raw message received from a client.

        Input:
            raw_message -> text received from socket

        Output:
            ParsedMessage -> structured result
    */
    ParsedMessage parse(const string &raw_message);
    /*
        Converts a MessageType enum into readable text.
        Useful for logging and terminal output.
    */
    static std::string messageTypeToString(MessageType type);

private:
    /*
        Removes leading and trailing whitespace/newline characters.
    */
    std::string trim(const std::string &input);

    // Parse legacy plain-text messages
    ParsedMessage parsePlainText(const string &message);

    // Parse JSON messages
    ParsedMessage parseJson(const string &message);
};

#endif