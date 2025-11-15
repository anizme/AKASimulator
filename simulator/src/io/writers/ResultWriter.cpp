#include "ResultWriter.hpp"
#include <algorithm>
#include <iomanip>
#include <cctype>

namespace Simulator
{
    bool ResultWriter::write(const Result<SimulationStatus> &result, const std::string &logFilePath)
    {
        try
        {
            std::string outputPath = buildOutputPath(logFilePath);

            std::ofstream outFile(outputPath);
            if (!outFile.is_open())
            {
                return false;
            }

            // For Result<SimulationStatus>, we care about the inner SimulationStatus value
            std::string status;
            std::string message;

            if (result.isSuccess())
            {
                // Get the actual SimulationStatus value
                SimulationStatus simStatus = result.value();
                status = statusToString(simStatus);
                message = result.errorMessage(); // This contains additional info if provided
            }
            else
            {
                // Result wrapper itself failed
                status = "Error";
                message = result.errorMessage();
            }

            // Write JSON
            outFile << "{\n";
            outFile << "  \"Status\": \"" << status << "\"";

            if (!message.empty())
            {
                outFile << ",\n";
                outFile << "  \"Message\": \"" << escapeJsonString(message) << "\"";

                // Add Location field for Error status
                if (status == "Error")
                {
                    std::string location = extractLocation(message);
                    if (!location.empty())
                    {
                        outFile << ",\n";
                        outFile << "  \"Location\": \"" << escapeJsonString(location) << "\"";
                    }
                }
            }

            outFile << "\n}\n";

            outFile.close();
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    std::string ResultWriter::extractFileName(const std::string &path) const
    {
        // Find last occurrence of '/' or '\'
        size_t lastSlash = path.find_last_of("/\\");
        std::string fileName;

        if (lastSlash != std::string::npos)
        {
            fileName = path.substr(lastSlash + 1);
        }
        else
        {
            fileName = path;
        }

        // Remove .log extension if present
        size_t dotPos = fileName.find_last_of('.');
        if (dotPos != std::string::npos)
        {
            fileName = fileName.substr(0, dotPos);
        }

        return fileName;
    }

    std::string ResultWriter::getDirectory(const std::string &path) const
    {
        size_t lastSlash = path.find_last_of("/\\");

        if (lastSlash != std::string::npos)
        {
            return path.substr(0, lastSlash + 1);
        }

        return "./";
    }

    std::string ResultWriter::escapeJsonString(const std::string &input) const
    {
        std::ostringstream escaped;

        for (char c : input)
        {
            switch (c)
            {
            case '"':
                escaped << "\\\"";
                break;
            case '\\':
                escaped << "\\\\";
                break;
            case '\b':
                escaped << "\\b";
                break;
            case '\f':
                escaped << "\\f";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    // Control characters
                    escaped << "\\u"
                            << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(c);
                }
                else
                {
                    escaped << c;
                }
                break;
            }
        }

        return escaped.str();
    }

    std::string ResultWriter::buildOutputPath(const std::string &logFilePath) const
    {
        std::string directory = getDirectory(logFilePath);
        std::string fileName = extractFileName(logFilePath);

        return directory + "AKA_SIMULATED_RESULT_" + fileName + ".json";
    }

    std::string ResultWriter::extractLocation(const std::string &message) const
    {
        // Find #AT marker
        size_t atPos = message.find("#AT");
        if (atPos == std::string::npos)
        {
            return "";
        }

        // Start after #AT (skip 3 characters)
        size_t startPos = atPos + 3;

        // Skip any leading whitespace
        while (startPos < message.length() && std::isspace(message[startPos]))
        {
            startPos++;
        }

        // Find the opening parenthesis '('
        size_t endPos = message.find('(', startPos);
        if (endPos == std::string::npos)
        {
            // If no '(' found, take until end of string
            endPos = message.length();
        }

        // Extract the location string
        std::string location = message.substr(startPos, endPos - startPos);

        // Trim trailing whitespace
        size_t lastNonSpace = location.find_last_not_of(" \t\n\r");
        if (lastNonSpace != std::string::npos)
        {
            location = location.substr(0, lastNonSpace + 1);
        }

        return location;
    }

    std::string ResultWriter::statusToString(SimulationStatus status) const
    {
        switch (status)
        {
        case SimulationStatus::NotStarted:
            return "NotStarted";
        case SimulationStatus::Running:
            return "Running";
        case SimulationStatus::Paused:
            return "Paused";
        case SimulationStatus::Success:
            return "Success";
        case SimulationStatus::Error:
            return "Error";
        case SimulationStatus::Timeout:
            return "Timeout";
        case SimulationStatus::Stopped:
            return "Stopped";
        default:
            return "Unknown";
        }
    }
} // namespace Simulator