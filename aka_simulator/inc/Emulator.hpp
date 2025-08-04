// aka_sumulator/inc/Emulator.hpp
#pragma once
#include "MemoryManager.hpp"
#include "ELFLoader.hpp"
#include "ExecutionLogger.hpp"
#include "EmulationCore.hpp"
#include <string>
#include <memory>

namespace STM32F103C8T6 {

class Emulator {
public:
    Emulator();
    ~Emulator() = default;

    // Main interface
    bool initialize(BootMode boot_mode = BootMode::Flash);
    bool loadELF(const std::string& elf_path);
    bool execute(const std::string& log_file_path);
    void cleanup();

    // Utility functions
    void printMemoryLayout() const;
    void printRegisters() const;

private:
    std::unique_ptr<MemoryManager> memory_manager_;
    std::unique_ptr<ELFLoader> elf_loader_;
    std::unique_ptr<ExecutionLogger> logger_;
    std::unique_ptr<EmulationCore> core_;
    
    ELFInfo elf_info_;
    BootMode boot_mode_;

    // Prevent copy and assignment
    Emulator(const Emulator&) = delete;
    Emulator& operator=(const Emulator&) = delete;
};

} // namespace STM32F103C8T6