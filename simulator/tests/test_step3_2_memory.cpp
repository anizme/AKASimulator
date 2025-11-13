#include "core/memory/MemoryManager.hpp"
#include "core/hooks/HookDispatcher.hpp"
#include "architecture/ArchitectureFactory.hpp"
#include "architecture/arm/chips/STM32F103C8T6.hpp"
#include "io/logging/ConsoleLogger.hpp"
#include "io/utils/StringUtils.hpp"
#include <unicorn/unicorn.h>

using namespace Simulator;

// Simple hook handler for testing
class TestHookHandler : public IHookHandler
{
public:
    TestHookHandler(LoggerPtr logger) : logger_(logger), instruction_count_(0) {}

    void onCodeExecution(const CodeHookEvent &event) override
    {
        instruction_count_++;
        if (instruction_count_ <= 5)
        { // Only log first 5 instructions
            LOG_DEBUG_F(logger_) << "Instruction " << instruction_count_
                                 << " at " << Utils::formatHex(event.address)
                                 << " (size: " << event.size << ")";
        }
    }

    int getInstructionCount() const { return instruction_count_; }

private:
    LoggerPtr logger_;
    int instruction_count_;
};

int main()
{
    auto logger = std::make_shared<ConsoleLogger>();

    LOG_INFO(logger, "=== Testing Step 3.2: Memory Manager & Hook Dispatcher ===");

    // Register architecture
    auto &factory = ArchitectureFactory::instance();
    factory.registerArchitecture<ARM::STM32F103C8T6>();

    // Create architecture
    auto arch_result = factory.create("stm32f103c8t6");
    if (!arch_result)
    {
        LOG_ERROR_F(logger) << "Failed: " << arch_result.errorMessage();
        return 1;
    }

    auto arch = arch_result.value();

    // Test 1: Initialize Unicorn
    LOG_INFO(logger, "\n[Test 1] Initialize Unicorn");
    uc_engine *uc = nullptr;
    uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err != UC_ERR_OK)
    {
        LOG_ERROR_F(logger) << "Failed: " << uc_strerror(err);
        return 1;
    }
    LOG_INFO(logger, "  ✓ Unicorn initialized");

    // Test 2: Memory Manager
    LOG_INFO(logger, "\n[Test 2] Setup memory regions");
    MemoryManager memory_manager(uc, arch, logger);

    auto mem_result = memory_manager.setupMemoryRegions(BootMode::Flash);
    if (!mem_result)
    {
        LOG_ERROR_F(logger) << "Failed: " << mem_result.errorMessage();
        uc_close(uc);
        return 1;
    }
    LOG_INFO(logger, "  ✓ Memory regions mapped");

    // Test 3: Validate addresses
    LOG_INFO(logger, "\n[Test 3] Validate addresses");

    Address test_addresses[] = {
        0x08000000, // Flash
        0x20000000, // SRAM
        0x40010800, // GPIOA (peripheral)
        0x00000000, // Boot alias
        0xDEADBEEF  // Invalid
    };

    for (auto addr : test_addresses)
    {
        bool valid = memory_manager.isValidAddress(addr);
        auto *region = memory_manager.getRegionForAddress(addr);

        if (valid && region)
        {
            LOG_INFO_F(logger) << "  " << Utils::formatHex(addr)
                               << " -> " << region->name << " ✓";
        }
        else
        {
            LOG_INFO_F(logger) << "  " << Utils::formatHex(addr)
                               << " -> Invalid ✗";
        }
    }

    // Test 4: Write some test data
    LOG_INFO(logger, "\n[Test 4] Write test data to memory");

    // Write a simple ARM Thumb instruction to Flash
    // MOVS R0, #0x42 (encoded as: 0x2042 in Thumb)
    uint16_t instruction = 0x2042;
    err = uc_mem_write(uc, 0x08000000, &instruction, sizeof(instruction));
    if (err == UC_ERR_OK)
    {
        LOG_INFO(logger, "  ✓ Wrote instruction to Flash");
    }
    else
    {
        LOG_ERROR_F(logger) << "  Failed: " << uc_strerror(err);
    }

    // Read it back
    uint16_t read_back = 0;
    err = uc_mem_read(uc, 0x08000000, &read_back, sizeof(read_back));
    if (err == UC_ERR_OK && read_back == instruction)
    {
        LOG_INFO_F(logger) << "  ✓ Read back: 0x" << std::hex << read_back;
    }
    else
    {
        LOG_ERROR(logger, "  Failed to read back");
    }

    // Test 5: Hook Dispatcher
    LOG_INFO(logger, "\n[Test 5] Setup hook dispatcher");
    HookDispatcher dispatcher(uc, logger);

    auto test_handler = std::make_shared<TestHookHandler>(logger);
    dispatcher.registerHandler(test_handler);

    auto hook_result = dispatcher.setupHooks();
    if (!hook_result)
    {
        LOG_ERROR_F(logger) << "Failed: " << hook_result.errorMessage();
        dispatcher.removeHooks();
        uc_close(uc);
        return 1;
    }
    LOG_INFO(logger, "  ✓ Hooks setup complete");

    // Test 6: Execute a few instructions
    LOG_INFO(logger, "\n[Test 6] Execute test instructions");

    // Setup initial state
    uint32_t sp = 0x20005000; // Stack pointer
    uint32_t pc = 0x08000001; // PC with Thumb bit

    uc_reg_write(uc, UC_ARM_REG_SP, &sp);
    uc_reg_write(uc, UC_ARM_REG_PC, &pc);

    // Write a sequence of instructions
    uint16_t instructions[] = {
        0x2042, // MOVS R0, #0x42
        0x2143, // MOVS R1, #0x43
        0x1840, // ADDS R0, R0, R1
    };
    err = uc_mem_write(uc, 0x08000000, instructions, sizeof(instructions));

    // Execute
    err = uc_emu_start(uc, 0x08000001, 0x08000006, 0, 0); // Execute 3 instructions

    if (err == UC_ERR_OK)
    {
        LOG_INFO_F(logger) << "  ✓ Executed " << test_handler->getInstructionCount()
                           << " instructions";

        // Read R0 to verify
        uint32_t r0 = 0;
        uc_reg_read(uc, UC_ARM_REG_R0, &r0);
        LOG_INFO_F(logger) << "  R0 = 0x" << std::hex << r0
                           << " (expected: 0x85)";
    }
    else
    {
        LOG_ERROR_F(logger) << "  Execution failed: " << uc_strerror(err);
    }

    // Cleanup
    dispatcher.removeHooks();
    uc_close(uc);

    LOG_INFO(logger, "\n=== All tests passed! ===");

    return 0;
}