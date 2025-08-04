// aka_simulator/src/Emulator.cpp

#include "Emulator.hpp"
#include <iostream>

namespace STM32F103C8T6 {

Emulator::Emulator() : boot_mode_(BootMode::Flash) {
    // Initialize all components as null pointers
    // They will be created in initialize()
}

bool Emulator::initialize(BootMode boot_mode) {
    std::cout << "Initializing STM32F103C8T6 Emulator..." << std::endl;
    
    boot_mode_ = boot_mode;

    // Initialize emulation core first
    core_ = std::make_unique<EmulationCore>();
    if (!core_->initialize(boot_mode)) {
        std::cerr << "Failed to initialize emulation core" << std::endl;
        return false;
    }

    // Create memory manager and setup memory regions
    // We need to get the Unicorn engine from EmulationCore
    // For now, we'll create a temporary workaround by passing the engine
    // In a real implementation, you might want to expose the engine or refactor further
    
    // Create other components
    memory_manager_ = std::make_unique<MemoryManager>(core_->getEngine(), boot_mode);
    if (!memory_manager_->setupMemoryRegions()) {
        std::cerr << "Failed to setup memory regions" << std::endl;
        return false;
    }

    elf_loader_ = std::make_unique<ELFLoader>(core_->getEngine());
    logger_ = std::make_unique<ExecutionLogger>();

    std::cout << "Emulator initialized successfully" << std::endl;
    printMemoryLayout();
    return true;
}

bool Emulator::loadELF(const std::string& elf_path) {
    if (!elf_loader_) {
        std::cerr << "Emulator not initialized" << std::endl;
        return false;
    }

    if (!elf_loader_->loadELF(elf_path, elf_info_)) {
        std::cerr << "Failed to load ELF file: " << elf_path << std::endl;
        return false;
    }

    // Setup initial CPU state with loaded ELF info
    if (!core_->setupInitialState(elf_info_)) {
        std::cerr << "Failed to setup initial CPU state" << std::endl;
        return false;
    }

    // Set main address in core for hook handling
    core_->setMainAddress(elf_info_.main_address);

    return true;
}

bool Emulator::execute(const std::string& log_file_path) {
    if (!core_ || !logger_) {
        std::cerr << "Emulator not properly initialized" << std::endl;
        return false;
    }

    // Initialize logger
    if (!logger_->initialize(log_file_path, elf_info_.file_path, 
                            elf_info_.entry_point, elf_info_.debug_state)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return false;
    }

    // Set logger in core for instruction logging
    core_->setLogger(logger_.get());

    // Start execution
    bool success = core_->execute(elf_info_.entry_point, 1000);

    // Close logger
    logger_->close();

    return success;
}

void Emulator::cleanup() {
    // Cleanup in reverse order
    logger_.reset();
    elf_loader_.reset();
    memory_manager_.reset();
    core_.reset();
    
    // Clear ELF info
    elf_info_ = ELFInfo{};
}

void Emulator::printMemoryLayout() const {
    if (memory_manager_) {
        memory_manager_->printLayout();
    } else {
        std::cout << "Memory manager not initialized" << std::endl;
    }
}

void Emulator::printRegisters() const {
    if (core_) {
        core_->printRegisters();
    } else {
        std::cout << "Emulation core not initialized" << std::endl;
    }
}

} // namespace STM32F103C8T6