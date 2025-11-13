#pragma once

#include "simulator/Types.hpp"
#include "io/logging/ILogger.hpp"
#include <string>
#include <memory>
#include <unicorn/unicorn.h>

namespace Simulator
{

    /**
     * @brief Loads ELF binaries and extracts information
     *
     * Responsibilities:
     * - Parse ELF file
     * - Extract segments (code, data)
     * - Find symbols (entry point, main, hooks)
     * - Write binary data to Unicorn memory
     */
    class ELFLoader
    {
    public:
        /**
         * @brief Constructor
         * @param uc Unicorn engine instance
         * @param logger Logger
         */
        ELFLoader(uc_engine *uc, LoggerPtr logger);

        /**
         * @brief Load ELF file
         * @param elf_path Path to ELF file
         * @return Binary info or error
         */
        Result<BinaryInfo> load(const std::string &elf_path);

    private:
        uc_engine *uc_;
        LoggerPtr logger_;

        // Load segments into memory
        bool loadSegments(const std::string &elf_path, BinaryInfo &info);

        // Find symbol addresses
        bool findSymbols(const std::string &elf_path, BinaryInfo &info);

        // Find a specific function address
        bool findFunctionAddress(const std::string &elf_path,
                                 const std::string &func_name,
                                 Address &addr);

        // Find a global variable address
        bool findGlobalVariableAddress(const std::string &elf_path,
                                       const std::string &var_name,
                                       Address &addr);
    };

} // namespace Simulator