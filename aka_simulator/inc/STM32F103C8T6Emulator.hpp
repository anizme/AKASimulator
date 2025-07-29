// aka_simulator/inc/STM32F103C8T6Emulator.hpp

#pragma once
#include <unicorn/unicorn.h>
#include <elfio/elfio.hpp>
#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <cstdint>

/**
 * STM32F103C8T6 Emulator
 * Version 1: Basic emulation with hex instruction logging
 */
class STM32F103C8T6Emulator
{
public:
    STM32F103C8T6Emulator();
    ~STM32F103C8T6Emulator();

    // Main interface
    bool initialize();
    bool loadELF(const std::string& elf_path);
    bool execute(const std::string& log_file_path);
    void cleanup();

    // Utility functions
    void printMemoryLayout() const;
    void printRegisters() const;

private:
    // STM32F103C8T6 Memory Map Constants
    static constexpr uint32_t FLASH_BASE = 0x08000000;
    static constexpr uint32_t FLASH_SIZE = 0x10000; // 64KB
    static constexpr uint32_t SRAM_BASE = 0x20000000;
    static constexpr uint32_t SRAM_SIZE = 0x00005000; // 20KB
    static constexpr uint32_t STACK_TOP = 0x20005000;  // Top of SRAM

    // Core components
    uc_engine* uc_engine_;
    std::ofstream log_file_;
    uint32_t entry_point_;
    std::string elf_path_;

    // Hook handles
    uc_hook code_hook_handle_;
    uc_hook invalid_mem_hook_handle_;

    // Private methods
    bool setupMemoryRegions();
    bool loadELFSegments();
    bool setupInitialState();
    bool openLogFile(const std::string& log_file_path);
    void closeLogFile();

    // Callback functions (must be static for C API)
    static void codeHookCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static bool invalidMemoryCallback(uc_engine* uc, uc_mem_type type, uint64_t address, 
                                     int size, int64_t value, void* user_data);
    
    // Helper methods for callbacks
    void handleCodeExecution(uint64_t address, uint32_t size);
    void handleInvalidMemory(uint64_t address, int size);
    
    // Utility methods
    void logHeader();
    void logInstruction(uint64_t address, const uint8_t* instruction_bytes, uint32_t size);
    std::string formatHexBytes(const uint8_t* bytes, uint32_t size) const;
    std::string getCurrentTimestamp() const;
    
    // Prevent copy and assignment
    STM32F103C8T6Emulator(const STM32F103C8T6Emulator&) = delete;
    STM32F103C8T6Emulator& operator=(const STM32F103C8T6Emulator&) = delete;

};