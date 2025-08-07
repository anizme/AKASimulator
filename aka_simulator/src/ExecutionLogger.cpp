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
                                     uint32_t entry_point, const std::string &addr2line_cmd)
    {
        elf_path_ = elf_path;
        addr2line_command_ = addr2line_cmd;
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

        std::cout << "Log file created: " << log_file_path << std::endl;
        writeHeader(entry_point);
        return true;
    }

    std::string ExecutionLogger::generateExecutedCodePath(const std::string &filePath)
    {
        std::filesystem::path path(filePath);

        //Remove extionsion
        std::string fileName = path.stem().string();

        std::filesystem::path parentPath = path.parent_path();

        std::string newFileName = "executed_code_" + fileName + ".log";

        std::filesystem::path outputPath = parentPath / newFileName;

        return outputPath.string();
    }

    void ExecutionLogger::logExecutedCode(const std::string &message) {
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
        if (!addr2line_command_.empty())
        {
            SourceInfo info = getSourceInfo(address);
            oss << dumpSourceInfo(info);
            logExecutedCode(dumpSourceInfoOnlyLineOfCode(info));
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
        if (executed_code_log_file_.is_open()) {
            executed_code_log_file_ << "# ERROR: " << message << std::endl;
            executed_code_log_file_.flush();
        }
        std::cerr << "[LOG] " + message << std::endl;
    }

    void ExecutionLogger::logInfo(const std::string &message, uint64_t address)
    {
        if (log_file_.is_open())
        {
            log_file_ << "# INFO: " << message << " at 0x" << std::hex << address << std::dec << std::endl;
            log_file_.flush();
        }
        if (executed_code_log_file_.is_open()) {
            executed_code_log_file_ << "# INFO: " << message << std::endl;
            executed_code_log_file_.flush();
        }
    }

    std::string ExecutionLogger::dumpSourceInfo(const SourceInfo &info)
    {
        std::string str;
        if (!info.filename.empty() && info.filename != "??")
        {
            str.append(info.filename).append(":").append(std::to_string(info.line_number));
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

    std::string ExecutionLogger::dumpSourceInfoOnlyLineOfCode(const SourceInfo &info) {
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
        // Not in cache, call addr2line
        std::string output = executeAddr2Line(address);
        SourceInfo info = parseAddr2LineOutput(output);

        // Cache the result (but limit cache size to prevent memory issues)
        if (address_cache_.size() < 10000)
        { // Limit cache to 10k entries
            address_cache_[address] = info;
        }

        return info;
    }

    std::string ExecutionLogger::executeAddr2Line(uint64_t address)
    {
        if (addr2line_command_.empty())
        {
            return "";
        }

        // Create the command with the address
        std::stringstream cmd_ss;
        cmd_ss << addr2line_command_ << " 0x" << std::hex << address;
        std::string command = cmd_ss.str();

        // Execute the command and capture output
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

        if (!pipe)
        {
            std::cerr << "Failed to execute addr2line command: " << command << std::endl;
            return "";
        }

        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr)
        {
            result += buffer;
        }
        return result;
    }

    SourceInfo ExecutionLogger::parseAddr2LineOutput(const std::string &output)
    {
        SourceInfo info;
        info.filename = "??";
        info.function = "??";
        info.line_number = 0;

        if (output.empty())
        {
            return info;
        }

        std::istringstream stream(output);
        std::string line;

        // addr2line with -a -f outputs: address, function name, then file:line
        // Skip the first line (address)
        if (std::getline(stream, line))
        {
            // First line is address, ignore it
        }

        // Second line is function name
        if (std::getline(stream, line))
        {
            if (!line.empty() && line != "??")
            {
                info.function = line;
                // Remove newline if present
                if (!info.function.empty() && info.function.back() == '\n')
                {
                    info.function.pop_back();
                }
            }
        }

        // Third line is file:line
        if (std::getline(stream, line))
        {
            if (!line.empty() && line != "??:0")
            {
                // Remove newline if present
                if (!line.empty() && line.back() == '\n')
                {
                    line.pop_back();
                }

                size_t colon_pos = line.find_last_of(':');
                if (colon_pos != std::string::npos)
                {
                    info.filename = line.substr(0, colon_pos);
                    try
                    {
                        info.line_number = std::stoi(line.substr(colon_pos + 1));
                    }
                    catch (const std::exception &)
                    {
                        info.line_number = 0;
                    }
                }
            }
        }
        return info;
    }

} // namespace STM32F103C8T6