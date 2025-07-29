// aka_simulator/src/STM32F103C8T6Emulator.cpp

#include "STM32F103C8T6Emulator.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstring>

STM32F103C8T6Emulator::STM32F103C8T6Emulator() 
    : uc_engine_(nullptr)
    , entry_point_(0)
    , code_hook_handle_(0)
    , invalid_mem_hook_handle_(0) {
}

STM32F103C8T6Emulator::~STM32F103C8T6Emulator() {
    cleanup();
}


bool STM32F103C8T6Emulator::initialize() {
    std::cout << "Initializing STM32F103C8T6 Emulator..." << std::endl;
    
    // Initialize Unicorn engine for ARM Cortex-M3 (Thumb mode)
    uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc_engine_);
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to initialize Unicorn engine: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    // Setup memory regions
    if (!setupMemoryRegions()) {
        std::cerr << "Failed to setup memory regions" << std::endl;
        return false;
    }
    
    // Setup hooks
    err = uc_hook_add(uc_engine_, &code_hook_handle_, UC_HOOK_CODE, 
                      (void*)codeHookCallback, this, 1, 0);
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to add code hook: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    // Setup invalid memory access hook
    err = uc_hook_add(uc_engine_, &invalid_mem_hook_handle_, 
                      UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                      (void*)invalidMemoryCallback, this, 1, 0);
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to add invalid memory hook: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    std::cout << "Emulator initialized successfully" << std::endl;
    printMemoryLayout();
    return true;
}


bool STM32F103C8T6Emulator::setupMemoryRegions() {
    uc_err err;
    
    // Map Flash memory (readable + executable) 
    err = uc_mem_map(uc_engine_, FLASH_BASE, FLASH_SIZE, UC_PROT_READ | UC_PROT_EXEC);
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to map Flash memory: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    // Map SRAM (readable + writable)
    err = uc_mem_map(uc_engine_, SRAM_BASE, SRAM_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to map SRAM: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    return true;
}


bool STM32F103C8T6Emulator::loadELF(const std::string& elf_path) {
    std::cout << "Loading ELF file: " << elf_path << std::endl;
    
    elf_path_ = elf_path;
    
    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        std::cerr << "Failed to load ELF file: " << elf_path << std::endl;
        return false;
    }
    
    // Get entry point
    entry_point_ = static_cast<uint32_t>(reader.get_entry());
    std::cout << "Entry point: 0x" << std::hex << entry_point_ << std::dec << std::endl;
    
    // Load program segments into memory
    for (int i = 0; i < reader.segments.size(); ++i) {
        const auto& segment = *reader.segments[i];
        
        if (segment.get_type() == ELFIO::PT_LOAD && segment.get_file_size() > 0) {
            uint64_t vaddr = segment.get_virtual_address();
            uint64_t size = segment.get_file_size();
            
            std::cout << "Loading segment " << i << ": 0x" << std::hex << vaddr 
                     << " (size: 0x" << size << ")" << std::dec << std::endl;
            
            // Write segment data to emulated memory
            uc_err err = uc_mem_write(uc_engine_, vaddr, segment.get_data(), size);
            if (err != UC_ERR_OK) {
                std::cerr << "Failed to write segment to memory: " << uc_strerror(err) << std::endl;
                return false;
            }
        }
    }
    
    // Setup initial CPU state
    if (!setupInitialState()) {
        return false;
    }
    
    std::cout << "ELF loaded successfully" << std::endl;
    return true;
}


bool STM32F103C8T6Emulator::setupInitialState() {
    // For STM32, the first word in Flash is initial stack pointer
    // The second word is the reset handler (entry point)
    uint32_t initial_sp, reset_handler;
    
    uc_err err = uc_mem_read(uc_engine_, FLASH_BASE, &initial_sp, sizeof(initial_sp));
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to read initial stack pointer: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    err = uc_mem_read(uc_engine_, FLASH_BASE + 4, &reset_handler, sizeof(reset_handler));
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to read reset handler: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    // Set stack pointer
    err = uc_reg_write(uc_engine_, UC_ARM_REG_SP, &initial_sp);
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to set stack pointer: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    // Set program counter to reset handler (with Thumb bit set)
    uint32_t pc = reset_handler | 1;  // Set Thumb bit for Cortex-M
    err = uc_reg_write(uc_engine_, UC_ARM_REG_PC, &pc);
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to set program counter: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    std::cout << "Initial state:" << std::endl;
    std::cout << "  Stack Pointer: 0x" << std::hex << initial_sp << std::endl;
    std::cout << "  Reset Handler: 0x" << reset_handler << std::dec << std::endl;
    
    return true;
}


bool STM32F103C8T6Emulator::execute(const std::string& log_file_path) {
    std::cout << "Starting emulation..." << std::endl;
    
    // Open log file
    if (!openLogFile(log_file_path)) {
        return false;
    }
    
    // Write log header
    logHeader();
    
    // Start emulation (no instruction limit, no timeout)
    uc_err err = uc_emu_start(uc_engine_, entry_point_ | 1, 0xFFFFFFFF, 0, 0);
    
    closeLogFile();
    
    if (err != UC_ERR_OK) {
        std::cerr << "Emulation failed: " << uc_strerror(err) << std::endl;
        return false;
    }
    
    std::cout << "Emulation completed successfully" << std::endl;
    return true;
}

bool STM32F103C8T6Emulator::openLogFile(const std::string& log_file_path) {
    log_file_.open(log_file_path);
    if (!log_file_.is_open()) {
        std::cerr << "Failed to open log file: " << log_file_path << std::endl;
        return false;
    }
    
    std::cout << "Log file created: " << log_file_path << std::endl;
    return true;
}

void STM32F103C8T6Emulator::closeLogFile() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void STM32F103C8T6Emulator::logHeader() {
    log_file_ << "# STM32F103C8T6 Emulation Log" << std::endl;
    log_file_ << "# ELF File: " << elf_path_ << std::endl;
    log_file_ << "# Start Time: " << getCurrentTimestamp() << std::endl;
    log_file_ << "# Entry Point: 0x" << std::hex << entry_point_ << std::dec << std::endl;
    log_file_ << "# Memory Layout:" << std::endl;
    log_file_ << "#   Flash: 0x" << std::hex << FLASH_BASE << " - 0x" 
              << (FLASH_BASE + FLASH_SIZE - 1) << std::endl;
    log_file_ << "#   SRAM:  0x" << SRAM_BASE << " - 0x" 
              << (SRAM_BASE + SRAM_SIZE - 1) << std::dec << std::endl;
    log_file_ << "# Format: ADDRESS: HEX_BYTES" << std::endl;
    log_file_ << "#" << std::endl;
    log_file_ << std::endl;
}

// Static callback function for code execution
void STM32F103C8T6Emulator::codeHookCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    STM32F103C8T6Emulator* emulator = static_cast<STM32F103C8T6Emulator*>(user_data);
    emulator->handleCodeExecution(address, size);
}

void STM32F103C8T6Emulator::handleCodeExecution(uint64_t address, uint32_t size) {
    // Read instruction bytes from memory
    std::vector<uint8_t> instruction_bytes(size);
    uc_err err = uc_mem_read(uc_engine_, address, instruction_bytes.data(), size);
    
    if (err != UC_ERR_OK) {
        std::cerr << "Failed to read instruction at 0x" << std::hex << address 
                  << ": " << uc_strerror(err) << std::dec << std::endl;
        return;
    }
    
    // Log the instruction
    logInstruction(address, instruction_bytes.data(), size);
}

// Static callback function for invalid memory access
bool STM32F103C8T6Emulator::invalidMemoryCallback(uc_engine* uc, uc_mem_type type, uint64_t address, 
                                             int size, int64_t value, void* user_data) {
    STM32F103C8T6Emulator* emulator = static_cast<STM32F103C8T6Emulator*>(user_data);
    emulator->handleInvalidMemory(address, size);
    return false; // Stop execution on invalid memory access
}

void STM32F103C8T6Emulator::handleInvalidMemory(uint64_t address, int size) {
    std::string error_msg = "INVALID MEMORY ACCESS: 0x" + 
                           std::to_string(address) + " (size: " + std::to_string(size) + ")";
    
    std::cerr << error_msg << std::endl;
    
    if (log_file_.is_open()) {
        log_file_ << "# ERROR: " << error_msg << std::endl;
        log_file_.flush();
    }
}

void STM32F103C8T6Emulator::logInstruction(uint64_t address, const uint8_t* instruction_bytes, uint32_t size) {
    if (!log_file_.is_open()) {
        return;
    }
    
    // Format: 0x08000228: 2100
    log_file_ << "0x" << std::hex << std::setfill('0') << std::setw(8) << address << ": ";
    log_file_ << formatHexBytes(instruction_bytes, size);
    log_file_ << std::endl;
    
    // Flush periodically for real-time monitoring
    static int instruction_count = 0;
    if (++instruction_count % 100 == 0) {
        log_file_.flush();
    }
}

std::string STM32F103C8T6Emulator::formatHexBytes(const uint8_t* bytes, uint32_t size) const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (uint32_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
        if (i < size - 1) {
            ss << " ";
        }
    }
    
    return ss.str();
}

std::string STM32F103C8T6Emulator::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void STM32F103C8T6Emulator::printMemoryLayout() const {
    std::cout << "Memory Layout:" << std::endl;
    std::cout << "  Flash: 0x" << std::hex << FLASH_BASE << " - 0x" 
              << (FLASH_BASE + FLASH_SIZE - 1) << " (" << std::dec << (FLASH_SIZE / 1024) << "KB)" << std::endl;
    std::cout << "  SRAM:  0x" << std::hex << SRAM_BASE << " - 0x" 
              << (SRAM_BASE + SRAM_SIZE - 1) << " (" << std::dec << (SRAM_SIZE / 1024) << "KB)" << std::endl;
}

void STM32F103C8T6Emulator::printRegisters() const {
    if (!uc_engine_) {
        std::cout << "Emulator not initialized" << std::endl;
        return;
    }
    
    uint32_t regs[16];
    int reg_ids[] = {UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                     UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                     UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                     UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC};
    
    for (int i = 0; i < 16; ++i) {
        uc_reg_read(uc_engine_, reg_ids[i], &regs[i]);
    }
    
    std::cout << "Registers:" << std::endl;
    for (int i = 0; i < 13; ++i) {
        std::cout << "R" << i << "=0x" << std::hex << std::setfill('0') << std::setw(8) << regs[i] << " ";
        if ((i + 1) % 4 == 0) std::cout << std::endl;
    }
    std::cout << "SP=0x" << regs[13] << " LR=0x" << regs[14] << " PC=0x" << regs[15] << std::dec << std::endl;
}

void STM32F103C8T6Emulator::cleanup() {
    closeLogFile();
    
    if (uc_engine_) {
        uc_close(uc_engine_);
        uc_engine_ = nullptr;
    }
}