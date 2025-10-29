// aka_simulator/src/Utils.cpp

#include "Utils.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace Utils
{

    int map_capstone_to_unicorn_reg(arm_reg capstone_reg)
    {
        switch (capstone_reg)
        {
        // General Purpose Registers
        case ARM_REG_R0:
            return UC_ARM_REG_R0;
        case ARM_REG_R1:
            return UC_ARM_REG_R1;
        case ARM_REG_R2:
            return UC_ARM_REG_R2;
        case ARM_REG_R3:
            return UC_ARM_REG_R3;
        case ARM_REG_R4:
            return UC_ARM_REG_R4;
        case ARM_REG_R5:
            return UC_ARM_REG_R5;
        case ARM_REG_R6:
            return UC_ARM_REG_R6;
        case ARM_REG_R7:
            return UC_ARM_REG_R7;
        case ARM_REG_R8:
            return UC_ARM_REG_R8;
        case ARM_REG_R9:
            return UC_ARM_REG_R9;
        case ARM_REG_R10:
            return UC_ARM_REG_R10;
        case ARM_REG_R11:
            return UC_ARM_REG_R11;
        case ARM_REG_R12:
            return UC_ARM_REG_R12;

        // Special Purpose Registers
        case ARM_REG_SP:
            return UC_ARM_REG_SP; // Stack Pointer
        case ARM_REG_LR:
            return UC_ARM_REG_LR; // Link Register
        case ARM_REG_PC:
            return UC_ARM_REG_PC; // Program Counter

        // State Registers (CPSR, SPSR)
        case ARM_REG_CPSR:
            return UC_ARM_REG_CPSR;
        case ARM_REG_SPSR:
            return UC_ARM_REG_SPSR;

        // FPU Registers
        case ARM_REG_S0:
            return UC_ARM_REG_S0;
        case ARM_REG_S1:
            return UC_ARM_REG_S1;
        case ARM_REG_S2:
            return UC_ARM_REG_S2;
        case ARM_REG_S3:
            return UC_ARM_REG_S3;
        case ARM_REG_S4:
            return UC_ARM_REG_S4;
        case ARM_REG_S5:
            return UC_ARM_REG_S5;
        case ARM_REG_S6:
            return UC_ARM_REG_S6;
        case ARM_REG_S7:
            return UC_ARM_REG_S7;
        case ARM_REG_S8:
            return UC_ARM_REG_S8;
        case ARM_REG_S9:
            return UC_ARM_REG_S9;
        case ARM_REG_S10:
            return UC_ARM_REG_S10;
        case ARM_REG_S11:
            return UC_ARM_REG_S11;
        case ARM_REG_S12:
            return UC_ARM_REG_S12;
        case ARM_REG_S13:
            return UC_ARM_REG_S13;
        case ARM_REG_S14:
            return UC_ARM_REG_S14;
        case ARM_REG_S15:
            return UC_ARM_REG_S15;
        case ARM_REG_S16:
            return UC_ARM_REG_S16;
        case ARM_REG_S17:
            return UC_ARM_REG_S17;
        case ARM_REG_S18:
            return UC_ARM_REG_S18;
        case ARM_REG_S19:
            return UC_ARM_REG_S19;
        case ARM_REG_S20:
            return UC_ARM_REG_S20;
        case ARM_REG_S21:
            return UC_ARM_REG_S21;
        case ARM_REG_S22:
            return UC_ARM_REG_S22;
        case ARM_REG_S23:
            return UC_ARM_REG_S23;
        case ARM_REG_S24:
            return UC_ARM_REG_S24;
        case ARM_REG_S25:
            return UC_ARM_REG_S25;
        case ARM_REG_S26:
            return UC_ARM_REG_S26;
        case ARM_REG_S27:
            return UC_ARM_REG_S27;
        case ARM_REG_S28:
            return UC_ARM_REG_S28;
        case ARM_REG_S29:
            return UC_ARM_REG_S29;
        case ARM_REG_S30:
            return UC_ARM_REG_S30;
        case ARM_REG_S31:
            return UC_ARM_REG_S31;

        // Double Precision Registers
        case ARM_REG_D0:
            return UC_ARM_REG_D0;
        case ARM_REG_D1:
            return UC_ARM_REG_D1;
        case ARM_REG_D2:
            return UC_ARM_REG_D2;
        case ARM_REG_D3:
            return UC_ARM_REG_D3;
        case ARM_REG_D4:
            return UC_ARM_REG_D4;
        case ARM_REG_D5:
            return UC_ARM_REG_D5;
        case ARM_REG_D6:
            return UC_ARM_REG_D6;
        case ARM_REG_D7:
            return UC_ARM_REG_D7;
        case ARM_REG_D8:
            return UC_ARM_REG_D8;
        case ARM_REG_D9:
            return UC_ARM_REG_D9;
        case ARM_REG_D10:
            return UC_ARM_REG_D10;
        case ARM_REG_D11:
            return UC_ARM_REG_D11;
        case ARM_REG_D12:
            return UC_ARM_REG_D12;
        case ARM_REG_D13:
            return UC_ARM_REG_D13;
        case ARM_REG_D14:
            return UC_ARM_REG_D14;
        case ARM_REG_D15:
            return UC_ARM_REG_D15;

        // State FPU Registers
        case ARM_REG_FPSCR:
            return UC_ARM_REG_FPSCR;

        default:
            throw std::runtime_error("Unsupported Capstone register ID: " + std::to_string(capstone_reg));
        }
    }

    std::string formatHexBytes(const uint8_t *bytes, uint32_t size)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (uint32_t i = 0; i < size; ++i)
        {
            ss << std::setw(2) << static_cast<int>(bytes[i]);
            if (i < size - 1)
            {
                ss << " ";
            }
        }

        return ss.str();
    }

    std::string getCurrentTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    bool findFunctionAddress(const std::string &elf_path, const std::string &func_name, uint32_t &addr)
    {
        ELFIO::elfio reader;
        if (!reader.load(elf_path))
            return false;

        ELFIO::section *symtab = nullptr;
        for (int i = 0; i < reader.sections.size(); ++i)
        {
            ELFIO::section *sec = reader.sections[i];
            if (sec->get_type() == ELFIO::SHT_SYMTAB)
            {
                symtab = sec;
                break;
            }
        }
        if (!symtab)
            return false;

        ELFIO::symbol_section_accessor symbols(reader, symtab);

        bool found = false;
        bool found_weak = false;
        uint32_t tmp_addr = 0;

        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j)
        {
            std::string name;
            ELFIO::Elf64_Addr value;
            ELFIO::Elf_Xword size;
            unsigned char bind, type, other;
            ELFIO::Elf_Half section_index;

            symbols.get_symbol(j, name, value, size, bind, type, section_index, other);

            if (name == func_name &&
                type == ELFIO::STT_FUNC &&
                section_index != ELFIO::SHN_UNDEF)
            {
                uint32_t aligned = static_cast<uint32_t>(value & ~1U);

                if (bind == ELFIO::STB_GLOBAL)
                {
                    addr = aligned;
                    return true;
                }
                else if (bind == ELFIO::STB_WEAK && !found_weak)
                {
                    tmp_addr = aligned;
                    found_weak = true;
                }
            }
        }

        if (found_weak)
        {
            addr = tmp_addr;
            return true;
        }
        return false;
    }
} // namespace Utils
