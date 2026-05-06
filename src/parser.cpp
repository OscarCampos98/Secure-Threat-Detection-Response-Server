#include "parser.h"

#include <sstream>
#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>

/*
    parser.cpp

    Purpose:
    Implements message parsing for both:
    - plain-text messages
    - JSON messages

    The parser does not decide threat severity.
    It only validates structure and converts raw input into ParsedMessage.
*/

using json = nlohmann::json;
using namespace std;

ParsedMessage Parser::parse(const string &raw_message)
{
    string cleaned_message = trim(raw_message);

    ParsedMessage result;
    result.raw = cleaned_message;

    if (cleaned_message.empty())
    {
        result.valid = false;
        result.type = MessageType::INVALID;
        result.error = "Empty message";
        return result;
    }

    /*
        If the message starts with '{', treat it as JSON.
        Otherwise, keep supporting the original plain-text format.
    */
    if (cleaned_message.front() == '{')
    {
        return parseJson(cleaned_message);
    }

    return parsePlainText(cleaned_message);
}

ParsedMessage Parser::parsePlainText(const string &message)
{
    ParsedMessage result;

    result.raw = message;
    result.valid = false;
    result.is_json = false;
    result.type = MessageType::INVALID;

    istringstream stream(message);

    string command;
    stream >> command;

    string payload;
    getline(stream, payload);
    payload = trim(payload);

    result.payload = payload;

    if (command == "HEARTBEAT")
    {
        result.valid = true;
        result.type = MessageType::HEARTBEAT;
        return result;
    }

    if (command == "STATUS")
    {
        if (payload.empty())
        {
            result.error = "STATUS message missing payload";
            result.type = MessageType::INVALID;
            return result;
        }

        result.valid = true;
        result.type = MessageType::STATUS;
        return result;
    }

    if (command == "ERROR")
    {
        if (payload.empty())
        {
            result.error = "ERROR message missing payload";
            result.type = MessageType::INVALID;
            return result;
        }

        result.valid = true;
        result.type = MessageType::ERROR;
        return result;
    }

    if (command == "COMMAND")
    {
        if (payload.empty())
        {
            result.error = "COMMAND message missing payload";
            result.type = MessageType::INVALID;
            return result;
        }

        result.valid = true;
        result.type = MessageType::COMMAND;
        return result;
    }

    result.type = MessageType::UNKNOWN;
    result.error = "Unknown message type";

    return result;
}

ParsedMessage Parser::parseJson(const string &message)
{
    ParsedMessage result;

    result.raw = message;
    result.valid = false;
    result.is_json = true;
    result.type = MessageType::INVALID;

    try
    {
        json parsed_json = json::parse(message);

        if (!parsed_json.is_object())
        {
            result.error = "JSON message must be an object";
            return result;
        }

        /*
            event_type is required because the threat engine needs it
            to understand what kind of event occurred.
        */
        if (!parsed_json.contains("event_type") || !parsed_json["event_type"].is_string())
        {
            result.error = "JSON message missing string field: event_type";
            return result;
        }

        result.event_type = parsed_json["event_type"].get<string>();

        /*
            useful for future logging, identity handling,
            replay protection, and richer detection rules.
        */
        if (parsed_json.contains("client_id") && parsed_json["client_id"].is_string())
        {
            result.client_id = parsed_json["client_id"].get<string>();
        }

        if (parsed_json.contains("timestamp") && parsed_json["timestamp"].is_string())
        {
            result.timestamp = parsed_json["timestamp"].get<string>();
        }

        if (parsed_json.contains("status") && parsed_json["status"].is_string())
        {
            result.status = parsed_json["status"].get<string>();
        }

        if (parsed_json.contains("request_id") && parsed_json["request_id"].is_string())
        {
            result.request_id = parsed_json["request_id"].get<string>();
        }

        // Extraxt domain field from JSON
        if (parsed_json.contains("domain") && parsed_json["domain"].is_string())
        {
            result.domain = parsed_json["domain"].get<string>();
        }

        /*
            Map JSON event_type into the existing MessageType enum.
        */
        if (result.event_type == "HEARTBEAT")
        {
            result.valid = true;
            result.type = MessageType::HEARTBEAT;
            result.payload = result.status;
            return result;
        }

        if (result.event_type == "STATUS")
        {
            if (result.status.empty())
            {
                result.error = "STATUS JSON message missing status";
                result.type = MessageType::INVALID;
                return result;
            }

            result.valid = true;
            result.type = MessageType::STATUS;
            result.payload = result.status;
            return result;
        }

        if (result.event_type == "ERROR")
        {
            if (result.status.empty())
            {
                result.error = "ERROR JSON message missing status";
                result.type = MessageType::INVALID;
                return result;
            }

            result.valid = true;
            result.type = MessageType::ERROR;
            result.payload = result.status;
            return result;
        }

        if (result.event_type == "COMMAND")
        {
            if (result.status.empty())
            {
                result.error = "COMMAND JSON message missing status";
                result.type = MessageType::INVALID;
                return result;
            }

            result.valid = true;
            result.type = MessageType::COMMAND;
            result.payload = result.status;
            return result;
        }

        if (result.event_type == "AUTH_ATTEMPT")
        {
            if (result.status.empty())
            {
                result.error = "AUTH_ATTEMPT JSON message missing status";
                result.type = MessageType::INVALID;
                return result;
            }

            result.valid = true;
            result.type = MessageType::AUTH_ATTEMPT;
            result.payload = result.status;
            return result;
        }

        // Add DNS_QUERY JSON mapping
        if (result.event_type == "DNS_QUERY")
        {
            if (result.status.empty())
            {
                result.error = "DNS_QUERY JSON message missing status";
                result.type = MessageType::INVALID;
                return result;
            }
            if (result.domain.empty())
            {
                result.error = "DNS_QUERY JSON message missing domain";
                result.type = MessageType::INVALID;
                return result;
            }

            result.valid = true;
            result.type = MessageType::DNS_QUERY;
            result.payload = result.status;
            return result;
        }

        result.type = MessageType::UNKNOWN;
        result.error = "Unknown JSON event_type";
        return result;
    }
    catch (const json::parse_error &error)
    {
        result.valid = false;
        result.type = MessageType::INVALID;
        result.error = string("JSON parse error: ") + error.what();
        return result;
    }
}

string Parser::messageTypeToString(MessageType type)
{
    switch (type)
    {
    case MessageType::HEARTBEAT:
        return "HEARTBEAT";

    case MessageType::STATUS:
        return "STATUS";

    case MessageType::ERROR:
        return "ERROR";

    case MessageType::COMMAND:
        return "COMMAND";

    case MessageType::AUTH_ATTEMPT:
        return "AUTH_ATTEMPT";

    case MessageType::DNS_QUERY:
        return "DNS_QUERY";

    case MessageType::UNKNOWN:
        return "UNKNOWN";

    case MessageType::INVALID:
        return "INVALID";

    default:
        return "INVALID";
    }
}

string Parser::trim(const string &input)
{
    auto start = find_if_not(input.begin(), input.end(), [](unsigned char ch)
                             { return isspace(ch); });

    auto end = find_if_not(input.rbegin(), input.rend(), [](unsigned char ch)
                           { return isspace(ch); })
                   .base();

    if (start >= end)
    {
        return "";
    }

    return string(start, end);
}