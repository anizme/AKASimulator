#pragma once

#include "Descriptors.hpp"
#include "simulator/Types.hpp"
#include <string>
#include <memory>

namespace Simulator
{

    /**
     * @brief Abstract interface for chip architectures
     *
     * Each chip implementation must provide:
     * - Memory map layout
     * - CPU configuration
     * - Boot settings
     *
     * This is METADATA ONLY - no execution logic here!
     */
    class IArchitecture
    {
    public:
        virtual ~IArchitecture() = default;

        /**
         * @brief Get chip identifier
         * @return Chip name (e.g., "stm32f103c8t6")
         */
        virtual std::string getChipName() const = 0;

        /**
         * @brief Get architecture type
         * @return Architecture type enum
         */
        virtual ArchitectureType getArchitectureType() const = 0;

        /**
         * @brief Get memory map descriptor
         * @return Complete memory layout
         */
        virtual MemoryMapDescriptor getMemoryMap() const = 0;

        /**
         * @brief Get CPU descriptor
         * @return CPU characteristics
         */
        virtual CPUDescriptor getCPUDescriptor() const = 0;

        /**
         * @brief Get boot descriptor
         * @return Boot configuration
         */
        virtual BootDescriptor getBootDescriptor() const = 0;

        /**
         * @brief Get peripheral descriptors (optional, for future)
         * @return List of peripherals
         */
        virtual std::vector<PeripheralDescriptor> getPeripherals() const
        {
            return {}; // Default: empty
        }

        /**
         * @brief Get human-readable description
         */
        virtual std::string getDescription() const
        {
            return getChipName();
        }
    };

    // Shared pointer type
    using ArchitecturePtr = std::shared_ptr<IArchitecture>;

} // namespace Simulator