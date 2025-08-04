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
        void logInstruction(uint64_t address, const uint8_t *instruction_bytes, uint32_t size);
        void logError(const std::string &message);
        void close();

    private:
        std::ofstream log_file_;
        std::string elf_path_;
        std::string addr2line_command_;
        int instruction_count_;

        // Cache for address-to-source mapping to avoid repeated addr2line calls
        std::unordered_map<uint64_t, SourceInfo> address_cache_;

        void writeHeader(uint32_t entry_point);
        std::string getCurrentTimestamp() const;
        std::string formatHexBytes(const uint8_t *bytes, uint32_t size) const;
        SourceInfo getSourceInfo(uint64_t address);
        std::string executeAddr2Line(uint64_t address);
        SourceInfo parseAddr2LineOutput(const std::string &output);
    };

} // namespace STM32F103C8T6