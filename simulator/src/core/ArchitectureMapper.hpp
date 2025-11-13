#pragma once

#include "simulator/Types.hpp"
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>


namespace Simulator
{

    /**
     * @brief Maps architecture metadata to Unicorn/Capstone constants
     *
     * This is the ONLY place that knows about Unicorn/Capstone.
     * Architecture module remains pure metadata.
     */
    class ArchitectureMapper
    {
    public:
        /**
         * @brief Get Unicorn architecture constant
         */
        static uc_arch getUnicornArch(ArchitectureType type)
        {
            switch (type)
            {
            case ArchitectureType::ARMCortexM3:
            case ArchitectureType::ARMCortexM4:
            case ArchitectureType::ARMCortexM7:
            case ArchitectureType::ARMCortexA:
                return UC_ARCH_ARM;

            case ArchitectureType::RISCV32:
            case ArchitectureType::RISCV64:
                return UC_ARCH_RISCV;

            case ArchitectureType::AVR:
                return UC_ARCH_MAX; // Unicorn doesn't support AVR

            case ArchitectureType::x86:
                return UC_ARCH_X86;

            default:
                return UC_ARCH_ARM; // Default
            }
        }

        /**
         * @brief Get Unicorn mode constant
         */
        static uc_mode getUnicornMode(ISA isa)
        {
            switch (isa)
            {
            case ISA::ARM:
                return UC_MODE_ARM;

            case ISA::Thumb:
            case ISA::Thumb2:
                return UC_MODE_THUMB;

            case ISA::ARM64:
                return UC_MODE_ARM; // ARM64 mode

            case ISA::RISCV32:
                return UC_MODE_RISCV32;

            case ISA::RISCV64:
                return UC_MODE_RISCV64;

            default:
                return UC_MODE_THUMB; // Default
            }
        }

        /**
         * @brief Get Capstone architecture constant
         */
        static cs_arch getCapstoneArch(ArchitectureType type)
        {
            switch (type)
            {
            case ArchitectureType::ARMCortexM3:
            case ArchitectureType::ARMCortexM4:
            case ArchitectureType::ARMCortexM7:
            case ArchitectureType::ARMCortexA:
                return CS_ARCH_ARM;

            case ArchitectureType::RISCV32:
            case ArchitectureType::RISCV64:
                return CS_ARCH_RISCV;

            case ArchitectureType::x86:
                return CS_ARCH_X86;

            default:
                return CS_ARCH_ARM;
            }
        }

        /**
         * @brief Get Capstone mode constant
         */
        static cs_mode getCapstoneMode(ISA isa)
        {
            switch (isa)
            {
            case ISA::ARM:
                return CS_MODE_ARM;

            case ISA::Thumb:
            case ISA::Thumb2:
                return CS_MODE_THUMB;

            case ISA::ARM64:
                return CS_MODE_ARM;

            case ISA::RISCV32:
                return CS_MODE_RISCV32;

            case ISA::RISCV64:
                return CS_MODE_RISCV64;

            default:
                return CS_MODE_THUMB;
            }
        }

        /**
         * @brief Check if architecture is supported by Unicorn
         */
        static bool isUnicornSupported(ArchitectureType type)
        {
            switch (type)
            {
            case ArchitectureType::ARMCortexM3:
            case ArchitectureType::ARMCortexM4:
            case ArchitectureType::ARMCortexM7:
            case ArchitectureType::ARMCortexA:
            case ArchitectureType::RISCV32:
            case ArchitectureType::RISCV64:
            case ArchitectureType::x86:
                return true;

            case ArchitectureType::AVR:
                return false; // Not supported

            default:
                return false;
            }
        }

        /**
         * @brief Get human-readable name for ISA
         */
        static const char *getISAName(ISA isa)
        {
            switch (isa)
            {
            case ISA::ARM:
                return "ARM";
            case ISA::Thumb:
                return "Thumb";
            case ISA::Thumb2:
                return "Thumb-2";
            case ISA::ARM64:
                return "ARM64";
            case ISA::RISCV32:
                return "RISC-V 32-bit";
            case ISA::RISCV64:
                return "RISC-V 64-bit";
            case ISA::AVR:
                return "AVR";
            case ISA::x86:
                return "x86";
            case ISA::x86_64:
                return "x86-64";
            default:
                return "Unknown";
            }
        }

        /**
         * @brief Get human-readable name for ArchitectureType
         */
        static const char *getArchitectureName(ArchitectureType type)
        {
            switch (type)
            {
            case ArchitectureType::ARMCortexM3:
                return "ARM Cortex-M3";
            case ArchitectureType::ARMCortexM4:
                return "ARM Cortex-M4";
            case ArchitectureType::ARMCortexM7:
                return "ARM Cortex-M7";
            case ArchitectureType::ARMCortexA:
                return "ARM Cortex-A";
            case ArchitectureType::RISCV32:
                return "RISC-V 32-bit";
            case ArchitectureType::RISCV64:
                return "RISC-V 64-bit";
            case ArchitectureType::AVR:
                return "AVR 8-bit";
            case ArchitectureType::x86:
                return "x86 32-bit";
            default:
                return "Unknown Architecture";
            }
        }
    };

} // namespace Simulator