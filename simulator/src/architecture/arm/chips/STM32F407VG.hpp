#pragma once

#include "../ARMCortexM3.hpp"

namespace Simulator
{
    namespace ARM
    {

        /**
         * @brief STM32F407VG chip definition (Cortex-M4)
         *
         * Specs:
         * - ARM Cortex-M4F @ 168MHz (with FPU)
         * - 1MB Flash
         * - 192KB SRAM
         * - High-performance device
         *
         * This demonstrates how easy it is to add new chips!
         */
        class STM32F407VG : public ARMCortexM3Base
        {
        public:
            std::string getChipName() const override
            {
                return "stm32f407vg";
            }

            std::string getDescription() const override
            {
                return "STM32F407VG (ARM Cortex-M4F, 1MB Flash, 192KB SRAM)";
            }

            ArchitectureType getArchitectureType() const override
            {
                return ArchitectureType::ARMCortexM4; // M4, not M3!
            }

            CPUDescriptor getCPUDescriptor() const override
            {
                CPUDescriptor cpu = ARMCortexM3Base::getCPUDescriptor();
                cpu.has_fpu = true;           // M4F has FPU!
                cpu.has_dsp = true;           // M4 has DSP instructions
                return cpu;
            }

            MemoryMapDescriptor getMemoryMap() const override
            {
                MemoryMapDescriptor map;

                // Much larger Flash and SRAM!
                map.addFlash(0x08000000, 1024 * 1024); // 1MB Flash
                map.addSRAM(0x20000000, 192 * 1024);   // 192KB SRAM

                // System memory
                map.addRegion(MemoryRegion(
                    "SystemMemory", 0x1FFF0000, 30 * 1024,
                    MemoryPermission::ReadExecute));

                // Option bytes
                map.addRegion(MemoryRegion(
                    "OptionBytes", 0x1FFFC000, 16,
                    MemoryPermission::Read));

                // (Peripherals similar to F103 but more of them)
                // Simplified for demo
                map.addPeripheral("APB1", 0x40000000, 0x10000);
                map.addPeripheral("APB2", 0x40010000, 0x10000);
                map.addPeripheral("AHB1", 0x40020000, 0x10000);
                map.addPeripheral("NVIC", 0xE000E000, 0x1000);

                return map;
            }

            BootDescriptor getBootDescriptor() const override
            {
                BootDescriptor boot = ARMCortexM3Base::getBootDescriptor();
                boot.vector_table_address = 0x08000000;
                boot.vector_table_size = 0x188; // More interrupts
                boot.boot_alias_target = 0x08000000;
                boot.boot_alias_size = 1024 * 1024;
                return boot;
            }
        };

    } // namespace ARM
} // namespace Simulator