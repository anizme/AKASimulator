#pragma once

#include "simulator/Types.hpp"
#include "core/hooks/HookDispatcher.hpp"
#include "io/logging/ILogger.hpp"
#include <unicorn/unicorn.h>
#include <string>
#include <vector>
#include <map>

namespace Simulator
{

    /**
     * @brief Function stub information
     */
    struct FunctionStub
    {
        std::string function_name;
        Address function_address;
        Address stub_address;

        FunctionStub() : function_address(0), stub_address(0) {}
    };

    /**
     * @brief Manages function stubs
     *
     * Responsibilities:
     * - Load stub definitions from file
     * - Find stub addresses in ELF
     * - Redirect calls to stubbed functions
     */
    class StubManager : public IHookHandler
    {
    public:
        /**
         * @brief Constructor
         * @param uc Unicorn engine instance
         * @param logger Logger
         */
        StubManager(uc_engine *uc, LoggerPtr logger);

        /**
         * @brief Load stub definitions from file
         * @param stub_file Path to stub file (one function name per line)
         * @return Success or error
         */
        Result<void> loadStubFile(const std::string &stub_file);

        /**
         * @brief Resolve stub addresses from ELF
         * @param elf_path Path to ELF file
         * @return Success or error
         */
        Result<void> resolveAddresses(const std::string &elf_path);

        /**
         * @brief Hook handler - redirect stubbed function calls
         */
        void onCodeExecution(const CodeHookEvent &event) override;

        /**
         * @brief Get number of stubs
         */
        size_t getStubCount() const { return stubs_.size(); }

        ArchitectureType arch_type; // Enum for type
        ISA isa;                    // Enum for ISA
    private:
        uc_engine *uc_;
        LoggerPtr logger_;

        std::vector<FunctionStub> stubs_;
        std::map<Address, FunctionStub *> address_to_stub_;

        // Find function address in ELF
        bool findFunctionAddress(const std::string &elf_path,
                                 const std::string &func_name,
                                 Address &address);
    };

} // namespace Simulator