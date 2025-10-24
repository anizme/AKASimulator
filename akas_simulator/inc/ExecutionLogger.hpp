// aka_simulator/inc/ELFLoader.hpp

#pragma once
#include <string>
#include <fstream>
#include <memory>
#include <unordered_map>
#include <algorithm>

namespace STM32F103C8T6
{

    struct SourceInfo
    {
        std::string filename;
        std::string function;
        int line_number;
        int col_number;
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
        void logAssert(const std::string &assertion, uint64_t address);
        void logAkaMark(uint64_t address);
        void close();

    private:
        std::ofstream log_file_;
        std::ofstream trace_file_;
        std::ofstream test_path_file_;
        std::string elf_path_;
        std::string trace_code_command_;
        int instruction_count_;
        SourceInfo previousSourceInfo_;

        // Cache for address-to-source mapping to avoid repeated calls
        std::unordered_map<uint64_t, SourceInfo> address_cache_;

        void writeHeader(uint32_t entry_point);
        SourceInfo getSourceInfo(uint64_t address);
        std::string executeMapping(uint64_t address);
        SourceInfo parseMappingOutput(const std::string &output);

        std::string dumpSourceInfo(const SourceInfo &info);
        std::string dumpSourceInfoOnlyLineOfCode(const SourceInfo &info);

        void appendSourceInfo(std::ostringstream &oss, uint64_t address);
        void writeLogLine(const std::string &line);

        std::string generateTraceFilePath(const std::string &filePath);
        std::string generateTestPathFilePath(const std::string &filePath);

        std::string readSourceLineAt(const SourceInfo &src);
    };

} // namespace STM32F103C8T6