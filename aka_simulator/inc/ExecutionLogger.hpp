// aka_simulator/inc/ELFLoader.hpp
#pragma once
#include <string>
#include <fstream>
#include <backtrace.h>

namespace STM32F103C8T6 {

class ExecutionLogger {
public:
    ExecutionLogger() = default;
    ~ExecutionLogger();

    bool initialize(const std::string& log_file_path, const std::string& elf_path, 
                   uint32_t entry_point, backtrace_state* debug_state);
    void logInstruction(uint64_t address, const uint8_t *instruction_bytes, uint32_t size);
    void logError(const std::string& message);
    void close();

private:
    std::ofstream log_file_;
    std::string elf_path_;
    backtrace_state* debug_state_;
    int instruction_count_;

    void writeHeader(uint32_t entry_point);
    std::string getCurrentTimestamp() const;
    std::string  formatHexBytes(const uint8_t *bytes, uint32_t size) const;
    static int backtraceCallback(void* data, uintptr_t pc, const char* filename, 
                                int lineno, const char* function);
    static void backtraceErrorCallback(void* data, const char* msg, int errnum);
};

} // namespace STM32F103C8T6