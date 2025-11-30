#pragma once

#include <string>
#include <fstream>
#include <sstream>
#include "simulator/Types.hpp"

namespace Simulator
{
    class ResultWriter
    {
    public:
        ResultWriter() = default;
        ~ResultWriter() = default;

        // Write result to JSON file - generic version
        template <typename T>
        bool write(const Result<T> &result, const std::string &logFilePath);

        // Specialized version for SimulationStatus
        bool write(const Result<SimulationStatus> &result, const std::string &logFilePath);

        std::string buildOutputPath(const std::string &logFilePath) const;

    private:
        // Extract filename from path
        std::string extractFileName(const std::string &path) const;

        // Get directory from path
        std::string getDirectory(const std::string &path) const;

        // Escape JSON string
        std::string escapeJsonString(const std::string &input) const;

        // Build output file path
        

        // Extract location from message (text after #AT until '(')
        std::string extractLocation(const std::string &message) const;

        // Convert SimulationStatus to string
        std::string statusToString(SimulationStatus status) const;
    };

    // Template implementation must be in header
    template <typename T>
    bool ResultWriter::write(const Result<T> &result, const std::string &logFilePath)
    {
        try
        {
            std::string outputPath = buildOutputPath(logFilePath);

            std::ofstream outFile(outputPath);
            if (!outFile.is_open())
            {
                return false;
            }

            // Write JSON
            outFile << "{\n";
            outFile << "  \"Status\": \"" << (result.isSuccess() ? "Success" : "Error") << "\",\n";
            outFile << "  \"Message\": \"" << escapeJsonString(result.errorMessage()) << "\"";

            // Add Location field for Error status
            if (result.isError())
            {
                std::string location = extractLocation(result.errorMessage());
                if (!location.empty())
                {
                    outFile << ",\n";
                    outFile << "  \"Location\": \"" << escapeJsonString(location) << "\"";
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
    };
} // namespace Simulator