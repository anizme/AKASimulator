// aka_simulator/src/ExecutionLogger.cpp

#include "ExecutionLogger.hpp"
#include "MemoryMap.hpp"
#include "Utils.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <cstring>
#include <filesystem>

namespace STM32F103C8T6
{

    ExecutionLogger::~ExecutionLogger()
    {
        close();
    }

    bool ExecutionLogger::initialize(const std::string &log_file_path, const std::string &elf_path,
                                     uint32_t entry_point, const std::string &trace_code_command)
    {
        elf_path_ = elf_path;
        trace_code_command_ = trace_code_command;
        instruction_count_ = 0;

        log_file_.open(log_file_path);
        if (!log_file_.is_open())
        {
            std::cerr << "Failed to open log file: " << log_file_path << std::endl;
            return false;
        }

        std::string executed_code_log_file_path = generateExecutedCodePath(log_file_path);
        executed_code_log_file_.open(executed_code_log_file_path);
        if (!executed_code_log_file_.is_open())
        {
            std::cerr << "Failed to open log file: " << executed_code_log_file_path << std::endl;
            return false;
        }

        std::string actuals_log_file_path = generateActualsPath(log_file_path);
        actuals_log_file_.open(actuals_log_file_path);
        if (!actuals_log_file_.is_open())
        {
            std::cerr << "Failed to open log file: " << actuals_log_file_path << std::endl;
            return false;
        }

        std::cout << "Log file created: " << log_file_path << std::endl;
        writeHeader(entry_point);
        return true;
    }

    std::string ExecutionLogger::generateExecutedCodePath(const std::string &filePath)
    {
        std::filesystem::path path(filePath);

        // Remove extionsion
        std::string fileName = path.stem().string();

        std::filesystem::path parentPath = path.parent_path();

        std::string newFileName = "code_line_" + fileName + ".log";

        std::filesystem::path outputPath = parentPath / newFileName;

        return outputPath.string();
    }

    std::string ExecutionLogger::generateActualsPath(const std::string &filePath)
    {
        std::filesystem::path path(filePath);

        // Remove extionsion
        std::string fileName = path.stem().string();

        std::filesystem::path parentPath = path.parent_path();

        std::string newFileName = "actuals_" + fileName + ".log";

        std::filesystem::path outputPath = parentPath / newFileName;

        return outputPath.string();
    }

    void ExecutionLogger::logExecutedCode(const std::string &message)
    {
        if (!executed_code_log_file_.is_open())
        {
            return;
        }
        std::ostringstream oss;
        oss << message << std::endl;
        executed_code_log_file_ << oss.str();
    }

    void ExecutionLogger::logInstructionRaw(uint64_t address, const uint8_t *instruction_bytes, uint32_t size)
    {
        if (!log_file_.is_open())
        {
            return;
        }

        // Use a osstringstream to capture backtrace output
        std::ostringstream oss;
        oss << "Instruction: 0x" << std::hex << std::setfill('0') << std::setw(8) << address << ": ";
        oss << Utils::formatHexBytes(instruction_bytes, size);

        appendSourceInfo(oss, address);
        writeLogLine(oss.str());
    }

    void ExecutionLogger::logInstructionAsm(uint64_t address, const char *mnemonic, const char *op_str)
    {
        if (!log_file_.is_open())
        {
            return;
        }

        // Format: [ADDRESS] MNEMONIC OPERANDS
        std::ostringstream oss;
        oss << "[0x" << std::hex << std::setfill('0') << std::setw(8) << address << "] ";
        oss << std::setfill(' ') << std::left << std::setw(8) << mnemonic;

        if (op_str && strlen(op_str) > 0)
        {
            oss << " " << op_str;
        }

        appendSourceInfo(oss, address);
        writeLogLine(oss.str());
    }

    void ExecutionLogger::appendSourceInfo(std::ostringstream &oss, uint64_t address)
    {
        oss << "\n\t|-> Code: ";
        if (!trace_code_command_.empty())
        {
            SourceInfo info = getSourceInfo(address);
            oss << dumpSourceInfo(info);
            logExecutedCode(dumpSourceInfo(info));
        }
        else
        {
            oss << "unknown (addr2line not available)";
        }
    }

    void ExecutionLogger::writeLogLine(const std::string &line)
    {
        log_file_ << line << std::endl;

        if (++instruction_count_ % 100 == 0)
        {
            log_file_.flush();
        }
    }

    void ExecutionLogger::logError(const std::string &message)
    {
        if (log_file_.is_open())
        {
            log_file_ << "# ERROR: " << message << std::endl;
            log_file_.flush();
        }
        if (executed_code_log_file_.is_open())
        {
            executed_code_log_file_ << "# ERROR: " << message << std::endl;
            executed_code_log_file_.flush();
        }
        std::cerr << "[LOG] " + message << std::endl;
    }

    void ExecutionLogger::logInfo(const std::string &message, uint64_t address)
    {
        if (log_file_.is_open())
        {
            log_file_ << message << " at 0x" << std::hex << address << std::dec << std::endl;
            log_file_.flush();
        }
        if (executed_code_log_file_.is_open())
        {
            executed_code_log_file_ << message << std::endl;
            executed_code_log_file_.flush();
        }
    }

    std::string ExecutionLogger::dumpSourceInfo(const SourceInfo &info)
    {
        std::string str;
        if (!info.filename.empty() && info.filename != "??")
        {
            str.append(info.filename).append(":").append(std::to_string(info.line_number)).append(":").append(std::to_string(info.col_number));
            if (!info.function.empty() && info.function != "??")
            {
                str.append(" (").append(info.function).append(")");
            }
        }
        else
        {
            str.append("unknown (no debug info)");
        }
        return str;
    }

    std::string ExecutionLogger::dumpSourceInfoOnlyLineOfCode(const SourceInfo &info)
    {
        std::string str;
        if (!info.filename.empty() && info.filename != "??")
        {
            str.append(info.filename).append(":").append(std::to_string(info.line_number));
        }
        else
        {
            str.append("unknown (no debug info)");
        }
        return str;
    }

    void ExecutionLogger::logAssert(const std::string &assertion, uint64_t address)
    {
        if (!actuals_log_file_.is_open())
        {
            return;
        }

        std::ostringstream oss;
        oss << assertion;
        appendSourceInfo(oss, address);

        if (actuals_log_file_.is_open())
        {
            actuals_log_file_ << oss.str() << std::endl;
            actuals_log_file_.flush();
        }
    }

    void ExecutionLogger::close()
    {
        if (log_file_.is_open())
        {
            log_file_.close();
        }
    }

    void ExecutionLogger::writeHeader(uint32_t entry_point)
    {
        log_file_ << "# STM32F103C8T6 Emulation Log" << std::endl;
        log_file_ << "# ELF File: " << elf_path_ << std::endl;
        log_file_ << "# Start Time: " << Utils::getCurrentTimestamp() << std::endl;
        log_file_ << "# Entry Point: 0x" << std::hex << entry_point << std::dec << std::endl;
        log_file_ << "# Memory Layout:" << std::endl;
        log_file_ << "# \tFlash: 0x" << std::hex << MemoryMap::FLASH_BASE << " - 0x"
                  << (MemoryMap::FLASH_BASE + MemoryMap::FLASH_SIZE - 1) << std::endl;
        log_file_ << "# \tSRAM:  0x" << MemoryMap::SRAM_BASE << " - 0x"
                  << (MemoryMap::SRAM_BASE + MemoryMap::SRAM_SIZE - 1) << std::dec << std::endl;
        log_file_ << "# Format: ADDRESS: FILE:LINE (FUNCTION)" << std::endl;
        log_file_ << "#" << std::endl;
        log_file_ << std::endl;
    }

    SourceInfo ExecutionLogger::getSourceInfo(uint64_t address)
    {
        // Check cache first
        auto it = address_cache_.find(address);
        if (it != address_cache_.end())
        {
            return it->second;
        }
        // Not in cache, call trace code tool
        std::string output = executeMapping(address);
        SourceInfo info = parseMappingOutput(output);

        // Cache the result (but limit cache size to prevent memory issues)
        if (address_cache_.size() < 10000)
        { // Limit cache to 10k entries
            address_cache_[address] = info;
        }

        return info;
    }

    std::string ExecutionLogger::executeMapping(uint64_t address)
    {
        if (trace_code_command_.empty())
        {
            return "";
        }

        // Create the command with the address
        std::stringstream cmd_ss;
        cmd_ss << trace_code_command_ << " 0x" << std::hex << address;
        std::string command = cmd_ss.str();

        // Execute the command and capture output
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

        if (!pipe)
        {
            std::cerr << "Failed to execute trace code tool command: " << command << std::endl;
            return "";
        }

        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr)
        {
            result += buffer;
        }
        return result;
    }

    SourceInfo ExecutionLogger::parseMappingOutput(const std::string &output)
    {
        SourceInfo info;
        info.filename = "??";
        info.function = "??";
        info.line_number = 0;
        info.col_number = 0;

        if (output.empty())
        {
            return info;
        }

        std::istringstream stream(output);
        std::string line;

        // llvm-symbolizer output format:
        // function_name\n
        // file:line:col\n
        // (có thể có thêm lines cho inlined functions nếu dùng --inlines)

        // First line is function name
        if (std::getline(stream, line))
        {
            if (!line.empty() && line != "??")
            {
                info.function = line;
                // Remove trailing newline/carriage return
                info.function.erase(std::remove(info.function.begin(), info.function.end(), '\n'), info.function.end());
                info.function.erase(std::remove(info.function.begin(), info.function.end(), '\r'), info.function.end());
            }
        }

        // Second line is file:line:col
        if (std::getline(stream, line))
        {
            if (!line.empty() && line != "??:0:0")
            {
                // Remove trailing newline/carriage return
                line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
                line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());

                // Parse file:line:col format
                size_t first_colon = line.find(':');
                if (first_colon != std::string::npos)
                {
                    info.filename = line.substr(0, first_colon);

                    size_t second_colon = line.find(':', first_colon + 1);
                    if (second_colon != std::string::npos)
                    {
                        try
                        {
                            // Extract line number
                            std::string line_str = line.substr(first_colon + 1, second_colon - first_colon - 1);
                            info.line_number = std::stoi(line_str);

                            // Extract column number
                            std::string col_str = line.substr(second_colon + 1);
                            info.col_number = std::stoi(col_str);
                        }
                        catch (const std::exception &)
                        {
                            info.line_number = 0;
                            info.col_number = 0;
                        }
                    }
                    else
                    {
                        // Fallback: only line number available
                        try
                        {
                            info.line_number = std::stoi(line.substr(first_colon + 1));
                        }
                        catch (const std::exception &)
                        {
                            info.line_number = 0;
                        }
                    }
                }
                else
                {
                    // No colon found, use whole line as filename
                    info.filename = line;
                }
            }
        }
        return info;
    }

} // namespace STM32F103C8T6