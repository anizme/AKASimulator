#pragma once

#include "simulator/Types.hpp"
#include <vector>
#include <string>

namespace Simulator
{

    // ============================================================================
    // MEMORY MAP DESCRIPTOR
    // ============================================================================

    /**
     * @brief Describes the memory layout of a chip
     *
     * Contains all memory regions: Flash, SRAM, peripherals, etc.
     */
    class MemoryMapDescriptor
    {
    public:
        MemoryMapDescriptor() = default;

        // Builder pattern for easy construction
        MemoryMapDescriptor &addRegion(const MemoryRegion &region)
        {
            regions_.push_back(region);
            return *this;
        }

        MemoryMapDescriptor &addFlash(Address base, Size size)
        {
            regions_.emplace_back("Flash", base, size,
                                  MemoryPermission::ReadExecute);
            return *this;
        }

        MemoryMapDescriptor &addSRAM(Address base, Size size)
        {
            regions_.emplace_back("SRAM", base, size,
                                  MemoryPermission::ReadWrite);
            return *this;
        }

        MemoryMapDescriptor &addPeripheral(const std::string &name,
                                           Address base, Size size)
        {
            regions_.emplace_back(name, base, size,
                                  MemoryPermission::ReadWrite);
            return *this;
        }

        const std::vector<MemoryRegion> &getRegions() const { return regions_; }

        // Helper to find specific regions
        const MemoryRegion *findRegion(const std::string &name) const
        {
            for (const auto &region : regions_)
            {
                if (region.name == name)
                {
                    return &region;
                }
            }
            return nullptr;
        }

        Address getFlashBase() const
        {
            auto *region = findRegion("Flash");
            return region ? region->base_address : 0;
        }

        Size getFlashSize() const
        {
            auto *region = findRegion("Flash");
            return region ? region->size : 0;
        }

        Address getSRAMBase() const
        {
            auto *region = findRegion("SRAM");
            return region ? region->base_address : 0;
        }

        Size getSRAMSize() const
        {
            auto *region = findRegion("SRAM");
            return region ? region->size : 0;
        }

    private:
        std::vector<MemoryRegion> regions_;
    };

    // ============================================================================
    // CPU DESCRIPTOR
    // ============================================================================

    /**
     * @brief Describes CPU characteristics
     */
    struct CPUDescriptor
    {
        std::string architecture;    // "ARM Cortex-M3"
        std::string instruction_set; // "Thumb-2"
        uint32_t core_frequency_mhz; // Default frequency

        // Register info
        int num_general_registers; // 13 for ARM (R0-R12)
        int register_width_bits;   // 32

        // Features
        bool has_fpu;
        bool has_mpu;
        bool has_dsp;

        CPUDescriptor()
            : core_frequency_mhz(0), num_general_registers(0),
              register_width_bits(0), has_fpu(false),
              has_mpu(false), has_dsp(false) {}
    };

    // ============================================================================
    // BOOT DESCRIPTOR
    // ============================================================================

    /**
     * @brief Describes boot configuration
     */
    struct BootDescriptor
    {
        BootMode default_boot_mode;

        // Vector table
        Address vector_table_address;
        Size vector_table_size;

        // Boot aliases (for memory remapping)
        Address boot_alias_base;   // Usually 0x00000000
        Address boot_alias_target; // Flash or SRAM depending on mode
        Size boot_alias_size;

        BootDescriptor()
            : default_boot_mode(BootMode::Flash),
              vector_table_address(0), vector_table_size(0),
              boot_alias_base(0), boot_alias_target(0), boot_alias_size(0) {}
    };

    // ============================================================================
    // PERIPHERAL DESCRIPTOR (Optional - for future)
    // ============================================================================

    /**
     * @brief Describes a peripheral (for future simulation)
     */
    struct PeripheralDescriptor
    {
        std::string name; // "GPIOA", "USART1"
        Address base_address;
        Size register_space_size;

        // For future: interrupt numbers, DMA channels, etc.

        PeripheralDescriptor(const std::string &n, Address addr, Size size)
            : name(n), base_address(addr), register_space_size(size) {}
    };

} // namespace Simulator