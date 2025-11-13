#pragma once

#include "simulator/Types.hpp"
#include "architecture/IArchitecture.hpp"
#include "io/logging/ILogger.hpp"
#include <unicorn/unicorn.h>
#include <memory>

namespace Simulator
{

    /**
     * @brief Manages memory mapping in Unicorn
     *
     * Responsibilities:
     * - Map memory regions according to architecture descriptor
     * - Handle boot mode aliases
     * - Validate memory operations
     */
    class MemoryManager
    {
    public:
        /**
         * @brief Constructor
         * @param uc Unicorn engine instance
         * @param architecture Architecture descriptor
         * @param logger Logger
         */
        MemoryManager(uc_engine *uc,
                      ArchitecturePtr architecture,
                      LoggerPtr logger);

        /**
         * @brief Setup all memory regions
         * @param boot_mode Boot mode (Flash, SRAM, SystemMemory)
         * @return Success or error
         */
        Result<void> setupMemoryRegions(BootMode boot_mode);

        /**
         * @brief Check if address is valid
         * @param address Address to check
         * @return true if address is in a mapped region
         */
        bool isValidAddress(Address address) const;

        /**
         * @brief Get region containing address
         * @param address Address to check
         * @return Pointer to region or nullptr
         */
        const MemoryRegion *getRegionForAddress(Address address) const;

        /**
         * @brief Print memory layout
         */
        void printMemoryLayout() const;

    private:
        uc_engine *uc_;
        ArchitecturePtr architecture_;
        LoggerPtr logger_;
        MemoryMapDescriptor memory_map_;
        BootDescriptor boot_descriptor_;

        // Map a single region
        Result<void> mapRegion(const MemoryRegion &region);

        // Map boot alias
        Result<void> mapBootAlias(BootMode boot_mode);

        // Convert MemoryPermission to Unicorn permissions
        int toUnicornPermission(MemoryPermission perm) const;
    };

} // namespace Simulator