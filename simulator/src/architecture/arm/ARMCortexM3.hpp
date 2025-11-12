#pragma once

#include "../IArchitecture.hpp"

namespace Simulator
{
    namespace ARM
    {

        /**
         * @brief Base class for ARM Cortex-M3 chips
         *
         * Provides common Cortex-M3 characteristics.
         * Specific chips inherit and override memory map.
         */
        class ARMCortexM3Base : public IArchitecture
        {
        public:
            ArchitectureType getArchitectureType() const override
            {
                return ArchitectureType::ARMCortexM3;
            }

            CPUDescriptor getCPUDescriptor() const override
            {
                CPUDescriptor cpu;
                cpu.architecture = "ARM Cortex-M3";
                cpu.instruction_set = "Thumb-2";
                cpu.core_frequency_mhz = 72;    // Common for STM32F1
                cpu.num_general_registers = 13; // R0-R12
                cpu.register_width_bits = 32;
                cpu.has_fpu = false; // M3 doesn't have FPU
                cpu.has_mpu = true;  // M3 has optional MPU
                cpu.has_dsp = false;
                return cpu;
            }

            BootDescriptor getBootDescriptor() const override
            {
                BootDescriptor boot;
                boot.default_boot_mode = BootMode::Flash;
                boot.boot_alias_base = 0x00000000;
                boot.boot_alias_size = 512 * 1024; // Max 512KB
                return boot;
            }
        };

    } // namespace ARM
} // namespace Simulator