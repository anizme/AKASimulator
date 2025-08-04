// aka_simulator/src/ExecutionLogger.cpp

#include "ExecutionLogger.hpp"
#include "MemoryMap.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>

namespace STM32F103C8T6 {

ExecutionLogger::~ExecutionLogger() {
    close();
}

bool ExecutionLogger::initialize(const std::string& log_file_path, const std::string& elf_path,
                                uint32_t entry_point, backtrace_state* debug_state) {
    elf_path_ = elf_path;
    debug_state_ = debug_state;
    instruction_count_ = 0;

    log_file_.open(log_file_path);
    if (!log_file_.is_open()) {
        std::cerr << "Failed to open log file: " << log_file_path << std::endl;
        return false;
    }

    std::cout << "Log file created: " << log_file_path << std::endl;
    writeHeader(entry_point);
    return true;
}

void ExecutionLogger::logInstruction(uint64_t address, const uint8_t *instruction_bytes, uint32_t size) {
    if (!log_file_.is_open()) {
        return;
    }

    // Use a stringstream to capture backtrace output
    std::stringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(8) << address << ": ";
    ss << formatHexBytes(instruction_bytes, size);
    ss << std::endl;

    // Call backtrace_pcinfo to get source information
    if (debug_state_) {
        int result = backtrace_pcinfo(debug_state_, address, backtraceCallback, 
                                     backtraceErrorCallback, &ss);
        if (result != 0) {
            ss << "unknown (no debug info)";
        }
    } else {
        ss << "unknown (no debug state)";
    }

    log_file_ << ss.str() << std::endl;

    // Flush periodically for real-time monitoring
    if (++instruction_count_ % 100 == 0) {
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

void ExecutionLogger::logError(const std::string& message) {
    if (log_file_.is_open()) {
        log_file_ << "# ERROR: " << message << std::endl;
        log_file_.flush();
    }
    std::cerr << message << std::endl;
}

void ExecutionLogger::close() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void ExecutionLogger::writeHeader(uint32_t entry_point) {
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

std::string ExecutionLogger::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int ExecutionLogger::backtraceCallback(void* data, uintptr_t pc, const char* filename, 
                                      int lineno, const char* function) {
    auto* stream = static_cast<std::stringstream*>(data);
    *stream << (filename ? filename : "??") << ":" << lineno << " (" 
            << (function ? function : "??") << ")";
    return 0;
}

void ExecutionLogger::backtraceErrorCallback(void* data, const char* msg, int errnum) {
    std::cerr << "libbacktrace error: " << msg << " (errnum=" << errnum << ")" << std::endl;
}

} // namespace STM32F103C8T6