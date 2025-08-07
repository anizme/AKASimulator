// aka_simulator/inc/ELFLoader.hpp

#pragma once
#include <string>
#include <fstream>
#include <memory>
#include <unordered_map>

namespace STM32F103C8T6
{

    struct SourceInfo
    {
        std::string filename;
        std::string function;
        int line_number;
    };

    class ExecutionLogger
    {
    public:
        ExecutionLogger() = default;
        ~ExecutionLogger();

        bool initialize(const std::string &log_file_path, const std::string &elf_path,
                        uint32_t entry_point, const std::string &addr2line_cmd);
        void logInstructionRaw(uint64_t address, const uint8_t *instruction_bytes, uint32_t size);
        void logInstructionAsm(uint64_t address, const char* mnemonic, const char* op_str);
        void logError(const std::string &message);
        void logInfo(const std::string &message, uint64_t address);
        void close();

    private:
        std::ofstream log_file_;
        std::string elf_path_;
        std::string addr2line_command_;
        int instruction_count_;

        // Cache for address-to-source mapping to avoid repeated addr2line calls
        std::unordered_map<uint64_t, SourceInfo> address_cache_;

        void writeHeader(uint32_t entry_point);
        SourceInfo getSourceInfo(uint64_t address);
        std::string executeAddr2Line(uint64_t address);
        SourceInfo parseAddr2LineOutput(const std::string &output);

        std::string dumpSourceInfo(const SourceInfo &info);

        void appendSourceInfo(std::ostringstream &oss, uint64_t address);
        void writeLogLine(const std::string &line);
    };

} // namespace STM32F103C8T6