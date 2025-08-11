// aka_simulator/inc/EmulationCore.hpp
#pragma once
#include "MemoryManager.hpp"
#include "ELFLoader.hpp"
#include "ExecutionLogger.hpp"
#include "Utils.hpp"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

namespace STM32F103C8T6
{

    enum class EmulationError
    {
        NONE,
        DIVISION_BY_ZERO,
    };

    class EmulationCore
    {
    public:
        EmulationCore();
        ~EmulationCore();
            
        EmulationError emu_error = EmulationError::NONE;

        bool initialize(BootMode boot_mode = BootMode::Flash);
        bool setupInitialState(const ELFInfo &elf_info);
        bool execute(uint32_t entry_point, uint32_t instruction_limit = 1000);
        void printRegisters() const;

        void setLogger(ExecutionLogger *logger) { logger_ = logger; }

        // Engine access (needed for other components)
        uc_engine *getEngine() const { return uc_engine_; }

    private:
        uc_engine *uc_engine_;
        uc_hook code_hook_handle_;
        uc_hook invalid_mem_hook_handle_;

        csh capstone_handle_;

        ELFInfo elf_info_;
        uint32_t main_return_address_ = -1;
        ExecutionLogger *logger_;

        bool setupHooks();
        bool setupCPUState(const ELFInfo &elf_info);

        // Static hook callbacks
        static void codeHookCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
        static bool invalidMemoryCallback(uc_engine *uc, uc_mem_type type, uint64_t address,
                                          int size, int64_t value, void *user_data);

        // Hook handlers
        void handleCodeExecution(uint64_t address, const uint8_t *instruction_bytes, uint32_t size);
        void handleInvalidMemory(uint64_t address, int size);
        void detectDivisionByZero(uc_engine *uc, uint64_t address, const uint8_t *code, size_t size);
    };

} // namespace STM32F103C8T6