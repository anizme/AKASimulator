// aka_simulator/src/EmulationCore.cpp

#include "EmulationCore.hpp"
#include "MemoryMap.hpp"
#include <iostream>
#include <iomanip>
#include <vector>

namespace STM32F103C8T6
{

    EmulationCore::EmulationCore()
        : uc_engine_(nullptr), code_hook_handle_(0), invalid_mem_hook_handle_(0),
          main_address_(0), lr_patched_(false), logger_(nullptr)
    {
    }

    EmulationCore::~EmulationCore()
    {
        if (uc_engine_)
        {
            uc_close(uc_engine_);
        }
    }

    bool EmulationCore::initialize(BootMode boot_mode)
    {
        std::cout << "[Initialize] Emulation Core..." << std::endl;

        // Initialize Unicorn engine for ARM Cortex-M3 (Thumb mode)
        uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc_engine_);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to initialize Unicorn engine: " << uc_strerror(err) << std::endl;
            return false;
        }

        std::cout << "Emulation Core initialized successfully" << std::endl;
        return true;
    }

    bool EmulationCore::setupInitialState(const ELFInfo &elf_info)
    {
        std::cout << "[Setup] Initial state..." << std::endl;
        if (!setupCPUState(elf_info))
        {
            return false;
        }

        std::cout << "[Setup] Hooks ..." << std::endl;
        if (!setupHooks())
        {
            return false;
        }

        main_address_ = elf_info.main_address;
        return true;
    }

    bool EmulationCore::setupCPUState(const ELFInfo &elf_info)
    {
        std::cout << "[Setup] CPU state..." << std::endl;
        // For STM32, the first word in Flash is initial stack pointer
        // The second word is the reset handler (entry point)
        uint32_t initial_sp, reset_handler;

        std::cout <<  "[Setup] Reading initial stack pointer and reset handler..." << std::endl;
        uc_err err = uc_mem_read(uc_engine_, MemoryMap::FLASH_BASE, &initial_sp, sizeof(initial_sp));
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to read initial stack pointer: " << uc_strerror(err) << std::endl;
            return false;
        }

        // Read reset handler (second word in Flash)
        err = uc_mem_read(uc_engine_, MemoryMap::FLASH_BASE + 4, &reset_handler, sizeof(reset_handler));
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to read reset handler: " << uc_strerror(err) << std::endl;
            return false;
        }

        // Set stack pointer
        err = uc_reg_write(uc_engine_, UC_ARM_REG_SP, &initial_sp);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to set stack pointer: " << uc_strerror(err) << std::endl;
            return false;
        }

        // Set program counter to reset handler (with Thumb bit set)
        uint32_t pc = reset_handler | 1; // Set Thumb bit for Cortex-M
        err = uc_reg_write(uc_engine_, UC_ARM_REG_PC, &pc);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to set program counter: " << uc_strerror(err) << std::endl;
            return false;
        }

        std::cout << "Initial CPU state:" << std::endl;
        std::cout << "\tStack Pointer: 0x" << std::hex << initial_sp << std::endl;
        std::cout << "\tReset Handler: 0x" << reset_handler << std::dec << std::endl;

        return true;
    }

    bool EmulationCore::setupHooks()
    {
        uc_err err;
        std::cout << "[Setup] Hook code instruction in full memory range" << std::endl;
        // Setup code execution hook
        err = uc_hook_add(uc_engine_, &code_hook_handle_, UC_HOOK_CODE,
                          (void *)codeHookCallback, this, 1, 0);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to add code hook: " << uc_strerror(err) << std::endl;
            return false;
        }

        // Setup invalid memory access hook
        // err = uc_hook_add(uc_engine_, &invalid_mem_hook_handle_,
        //                   UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
        //                   (void *)invalidMemoryCallback, this, 1, 0);
        // if (err != UC_ERR_OK)
        // {
        //     std::cerr << "Failed to add invalid memory hook: " << uc_strerror(err) << std::endl;
        //     return false;
        // }

        return true;
    }

    bool EmulationCore::execute(uint32_t entry_point, uint32_t instruction_limit)
    {
        std::cout << "[Execute] Starting emulation..." << std::endl;

        // Start emulation
        uc_err err = uc_emu_start(uc_engine_, entry_point | 1, 0xFFFFFFFF, 0, instruction_limit);
        std::cout << "[Result] ";
        if (err == UC_ERR_OK)
        {
            std::cout << "Emulation completed successfully" << std::endl;
        }
        else if (err == UC_ERR_READ_UNMAPPED || err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED)
        {
            uint32_t pc = 0;
            uc_reg_read(uc_engine_, UC_ARM_REG_PC, &pc);
            std::cerr << uc_strerror(err) << std::endl;
            logger_->logError(std::string(uc_strerror(err)) + ": Invalid memory access at PC: 0x" + std::to_string(pc));
            return false;
        }
        else if (err == UC_ERR_WRITE_PROT || err == UC_ERR_READ_PROT || err == UC_ERR_FETCH_PROT)
        {
            uint64_t pc = 0;
            uc_reg_read(uc_engine_, UC_ARM_REG_PC, &pc);
            std::cerr << uc_strerror(err) << std::endl;
            logger_->logError(std::string(uc_strerror(err)) + ": Invalid memory access at PC: 0x" + std::to_string(pc));
            return false;
        }
        else
        {
            std::cerr << "Emulation failed: " << uc_strerror(err) << std::endl;
            return false;
        }

        return true;
    }

    void EmulationCore::printRegisters() const
    {
        if (!uc_engine_)
        {
            std::cout << "Emulator not initialized" << std::endl;
            return;
        }

        uint32_t regs[16];
        int reg_ids[] = {UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                         UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                         UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                         UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC};

        for (int i = 0; i < 16; ++i)
        {
            uc_reg_read(uc_engine_, reg_ids[i], &regs[i]);
        }

        std::cout << "Registers:" << std::endl;
        for (int i = 0; i < 13; ++i)
        {
            std::cout << "R" << i << "=0x" << std::hex << std::setfill('0') << std::setw(8) << regs[i] << " ";
            if ((i + 1) % 4 == 0)
                std::cout << std::endl;
        }
        std::cout << "SP=0x" << regs[13] << " LR=0x" << regs[14] << " PC=0x" << regs[15] << std::dec << std::endl;
    }

    // Static callback functions
    void EmulationCore::codeHookCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    {
        EmulationCore *core = static_cast<EmulationCore *>(user_data);
        // Read instruction bytes from memory
        std::vector<uint8_t> instruction_bytes(size);
        uc_err err = uc_mem_read(uc, address, instruction_bytes.data(), size);

        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to read instruction at 0x" << std::hex << address
                      << ": " << uc_strerror(err) << std::dec << std::endl;
            return;
        }
        core->handleCodeExecution(address, instruction_bytes.data(), size);
    }

    bool EmulationCore::invalidMemoryCallback(uc_engine *uc, uc_mem_type type, uint64_t address,
                                              int size, int64_t value, void *user_data)
    {
        EmulationCore *core = static_cast<EmulationCore *>(user_data);
        core->handleInvalidMemory(address, size);
        return false; // Stop execution on invalid memory access
    }

    void EmulationCore::handleCodeExecution(uint64_t address, const uint8_t *instruction_bytes, uint32_t size)
    {
        // Assign LR to STOP_ADDR when entering main
        if (address == main_address_)
        {
            if (!lr_patched_)
            {
                uc_reg_write(uc_engine_, UC_ARM_REG_LR, &MemoryMap::STOP_ADDR);
                lr_patched_ = true;
                std::cout << "[Hook] Set LR to STOP_ADDR at entry of main" << std::endl;
            }
        }

        // Check if we reached the stop address
        // There is a case that main have not returned but an instruction access invalidly to this stop address
        if (address == MemoryMap::STOP_ADDR)
        {
            std::cout << "[Hook] Reached STOP_ADDR (main returned), stopping..." << std::endl;
            uc_emu_stop(uc_engine_);
            logger_->logInfo("Main function returned at ", address);
            return;
        }

        // Log the instruction if logger is available
        if (logger_)
        {
            logger_->logInstruction(address, instruction_bytes, size);
        }
    }

    void EmulationCore::handleInvalidMemory(uint64_t address, int size)
    {
        std::string error_msg = "INVALID MEMORY ACCESS: 0x" +
                                std::to_string(address) + " (size: " + std::to_string(size) + ")";

        if (logger_)
        {
            logger_->logError(error_msg);
        }
        else
        {
            std::cerr << error_msg << std::endl;
        }
    }

} // namespace STM32F103C8T6
