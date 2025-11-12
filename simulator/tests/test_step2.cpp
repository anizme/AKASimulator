#include "architecture/ArchitectureFactory.hpp"
#include "architecture/arm/chips/STM32F103C8T6.hpp"
#include "architecture/arm/chips/STM32F407VG.hpp"
#include "io/logging/ConsoleLogger.hpp"
#include <iostream>
#include <iomanip>

using namespace Simulator;

void printMemoryMap(const MemoryMapDescriptor &map, LoggerPtr logger)
{
    LOG_INFO(logger, "Memory Map:");
    for (const auto &region : map.getRegions())
    {
        LOG_INFO_F(logger) << "  " << region.name
                           << ": 0x" << std::hex << region.base_address
                           << " - 0x" << (region.base_address + region.size - 1)
                           << " (" << std::dec << (region.size / 1024) << " KB)";
    }
}

void printCPUInfo(const CPUDescriptor &cpu, LoggerPtr logger)
{
    LOG_INFO(logger, "CPU Info:");
    LOG_INFO_F(logger) << "  Architecture: " << cpu.architecture;
    LOG_INFO_F(logger) << "  Instruction Set: " << cpu.instruction_set;
    LOG_INFO_F(logger) << "  Frequency: " << cpu.core_frequency_mhz << " MHz";
    LOG_INFO_F(logger) << "  Registers: " << cpu.num_general_registers
                       << " x " << cpu.register_width_bits << "-bit";
    LOG_INFO_F(logger) << "  FPU: " << (cpu.has_fpu ? "Yes" : "No");
    LOG_INFO_F(logger) << "  DSP: " << (cpu.has_dsp ? "Yes" : "No");
}

void printBootInfo(const BootDescriptor &boot, LoggerPtr logger)
{
    LOG_INFO(logger, "Boot Info:");
    LOG_INFO_F(logger) << "  Vector Table: 0x" << std::hex << boot.vector_table_address
                       << " (size: 0x" << boot.vector_table_size << ")";
    LOG_INFO_F(logger) << "  Boot Alias: 0x" << boot.boot_alias_base
                       << " -> 0x" << boot.boot_alias_target;
}

int main()
{
    auto logger = std::make_shared<ConsoleLogger>();

    LOG_INFO(logger, "=== Testing Step 2: Architecture Module ===");

    // Test 1: Factory registration
    LOG_INFO(logger, "\n[Test 1] Architecture Factory");
    {
        auto &factory = ArchitectureFactory::instance();

        LOG_INFO_F(logger) << "Available chips: " << factory.getAvailableChips();

        if (factory.hasChip("stm32f103c8t6"))
        {
            LOG_INFO(logger, "  ✓ STM32F103C8T6 registered");
        }

        if (factory.hasChip("stm32f407vg"))
        {
            LOG_INFO(logger, "  ✓ STM32F407VG registered");
        }
    }

    // Test 2: Create STM32F103C8T6
    LOG_INFO(logger, "\n[Test 2] STM32F103C8T6 Architecture");
    {
        auto result = ArchitectureFactory::instance().create("stm32f103c8t6");

        if (!result)
        {
            LOG_ERROR_F(logger) << "Failed: " << result.errorMessage();
            return 1;
        }

        auto arch = result.value();
        LOG_INFO_F(logger) << "Created: " << arch->getDescription();

        auto map = arch->getMemoryMap();
        auto cpu = arch->getCPUDescriptor();
        auto boot = arch->getBootDescriptor();

        LOG_INFO_F(logger) << "Flash: 0x" << std::hex << map.getFlashBase()
                           << " (" << std::dec << (map.getFlashSize() / 1024) << " KB)";
        LOG_INFO_F(logger) << "SRAM:  0x" << std::hex << map.getSRAMBase()
                           << " (" << std::dec << (map.getSRAMSize() / 1024) << " KB)";

        LOG_INFO(logger, "  ✓ STM32F103C8T6 architecture works");
    }

    // Test 3: Create STM32F407VG
    LOG_INFO(logger, "\n[Test 3] STM32F407VG Architecture");
    {
        auto result = ArchitectureFactory::instance().create("stm32f407vg");

        if (!result)
        {
            LOG_ERROR_F(logger) << "Failed: " << result.errorMessage();
            return 1;
        }

        auto arch = result.value();
        LOG_INFO_F(logger) << "Created: " << arch->getDescription();

        auto map = arch->getMemoryMap();
        auto cpu = arch->getCPUDescriptor();

        LOG_INFO_F(logger) << "Flash: " << (map.getFlashSize() / 1024) << " KB";
        LOG_INFO_F(logger) << "SRAM:  " << (map.getSRAMSize() / 1024) << " KB";
        LOG_INFO_F(logger) << "Has FPU: " << (cpu.has_fpu ? "Yes" : "No");

        LOG_INFO(logger, "  ✓ STM32F407VG architecture works");
    }

    // Test 4: Invalid chip
    LOG_INFO(logger, "\n[Test 4] Invalid chip name");
    {
        auto result = ArchitectureFactory::instance().create("invalid_chip");

        if (!result)
        {
            LOG_INFO_F(logger) << "  ✓ Correctly rejected: " << result.errorMessage();
        }
        else
        {
            LOG_ERROR(logger, "Should have failed!");
            return 1;
        }
    }

    // Test 5: Detailed info dump
    LOG_INFO(logger, "\n[Test 5] Detailed STM32F103C8T6 Info");
    {
        auto arch = ArchitectureFactory::instance().create("stm32f103c8t6").value();

        printMemoryMap(arch->getMemoryMap(), logger);
        std::cout << std::endl;
        printCPUInfo(arch->getCPUDescriptor(), logger);
        std::cout << std::endl;
        printBootInfo(arch->getBootDescriptor(), logger);
    }

    LOG_INFO(logger, "\n=== All tests passed! ===");

    return 0;
}