#pragma once

#include "../IArchitecture.hpp"
#include "simulator/Types.hpp"

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
                CPUDescriptor cpu(ArchitectureType::ARMCortexM3, ISA::Thumb2);
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