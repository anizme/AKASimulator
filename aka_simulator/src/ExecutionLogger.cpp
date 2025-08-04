// aka_simulator/src/ExecutionLogger.cpp

#include "ExecutionLogger.hpp"
#include "MemoryMap.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstdlib>
#include <memory>

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

        std::cout << "Log file created: " << log_file_path << std::endl;
        writeHeader(entry_point);
        return true;
    }

    void ExecutionLogger::logInstruction(uint64_t address, const uint8_t *instruction_bytes, uint32_t size)
    {
        if (!log_file_.is_open())
        {
            return;
        }

        // Use a stringstream to capture backtrace output
        std::stringstream ss;
        ss << "0x" << std::hex << std::setfill('0') << std::setw(8) << address << ": ";
        ss << formatHexBytes(instruction_bytes, size);
        ss << std::endl;

        // Get source information
        if (!addr2line_command_.empty())
        {
            SourceInfo info = getSourceInfo(address);
            if (!info.filename.empty() && info.filename != "??")
            {
                ss << info.filename << ":" << info.line_number;
                if (!info.function.empty() && info.function != "??")
                {
                    ss << " (" << info.function << ")";
                }
            }
            else
            {
                ss << "unknown (no debug info)";
            }
        }
        else
        {
            ss << "unknown (addr2line not available)";
        }

        log_file_ << ss.str() << std::endl;

        // Flush periodically for real-time monitoring
        if (++instruction_count_ % 100 == 0)
        {
            log_file_.flush();
        }
    }

    std::string ExecutionLogger::formatHexBytes(const uint8_t *bytes, uint32_t size) const
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (uint32_t i = 0; i < size; ++i)
        {
            ss << std::setw(2) << static_cast<int>(bytes[i]);
            if (i < size - 1)
            {
                ss << " ";
            }
        }

        return ss.str();
    }

    void ExecutionLogger::logError(const std::string &message)
    {
        if (log_file_.is_open())
        {
            log_file_ << "# ERROR: " << message << std::endl;
            log_file_.flush();
        }
        std::cerr << message << std::endl;
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
        log_file_ << "# Start Time: " << getCurrentTimestamp() << std::endl;
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

    std::string ExecutionLogger::getCurrentTimestamp() const
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
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

        // addr2line with -f flag outputs function name first, then file:line
        if (std::getline(stream, line))
        {
            // First line is function name
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

        if (std::getline(stream, line))
        {
            // Second line is file:line
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

                    // Extract just the filename (not full path) for cleaner output
                    size_t slash_pos = info.filename.find_last_of('/');
                    if (slash_pos != std::string::npos && slash_pos + 1 < info.filename.length())
                    {
                        info.filename = info.filename.substr(slash_pos + 1);
                    }
                }
            }
        }

        return info;
    }

} // namespace STM32F103C8T6