#include "Symbolizer.hpp"
#include "StringUtils.hpp"
#include <cstdio>
#include <memory>
#include <array>
#include <sstream>

namespace Simulator
{

    Symbolizer::Symbolizer(const std::string &binary_path, LoggerPtr logger)
        : binary_path_(binary_path), logger_(logger)
    {
    }

    SourceInfo Symbolizer::resolve(Address address)
    {
        // Check cache first
        auto it = cache_.find(address);
        if (it != cache_.end())
        {
            return it->second;
        }

        // Execute command
        std::string output = executeCommand(address);

        // Parse output
        SourceInfo info = parseOutput(output);
        // Cache result (limit cache size to avoid memory issues)
        if (cache_.size() < 10000)
        {
            cache_[address] = info;
        }
        
        return info;
    }

    std::string Symbolizer::executeCommand(Address address)
    {
        // Build command: llvm-symbolizer -e <binary> <address>
        std::ostringstream cmd;
        cmd << "llvm-symbolizer -e " << binary_path_
            << " 0x" << std::hex << address;

        // Execute command and capture output
        std::string result;
        std::array<char, 128> buffer;

        std::unique_ptr<FILE, decltype(&pclose)> pipe(
            popen(cmd.str().c_str(), "r"),
            pclose);

        if (!pipe)
        {
            LOG_ERROR(logger_, "Failed to execute llvm-symbolizer");
            return "";
        }

        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
        {
            result += buffer.data();
        }

        return result;
    }

    SourceInfo Symbolizer::parseOutput(const std::string &output)
    {
        SourceInfo info;

        if (output.empty())
        {
            return info;
        }

        // llvm-symbolizer output format:
        // Line 1: function_name
        // Line 2: file:line:column

        std::istringstream stream(output);
        std::string line;

        // First line: function name
        if (std::getline(stream, line))
        {
            line = Utils::trim(line);
            if (!line.empty() && line != "??")
            {
                info.function_name = line;
            }
        }

        // Second line: file:line:column
        if (std::getline(stream, line))
        {
            line = Utils::trim(line);
            if (!line.empty() && line != "??:0:0")
            {
                // Parse file:line:column
                auto parts = Utils::split(line, ':');
                if (parts.size() >= 2)
                {
                    info.filename = parts[0];

                    try
                    {
                        info.line_number = std::stoi(parts[1]);

                        if (parts.size() >= 3)
                        {
                            info.column_number = std::stoi(parts[2]);
                        }
                    }
                    catch (...)
                    {
                        // Ignore parse errors
                    }
                }
            }
        }

        return info;
    }

} // namespace Simulator