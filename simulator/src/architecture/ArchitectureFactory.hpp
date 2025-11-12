#pragma once

#include "IArchitecture.hpp"
#include "simulator/Types.hpp"
#include "arm/chips/STM32F103C8T6.hpp"
#include "arm/chips/STM32F407VG.hpp"
#include <map>
#include <functional>
#include <memory>
#include <string>

namespace Simulator
{

    /**
     * @brief Register all available architectures
     *
     * This function is called once at startup to register
     * all chip implementations.
     */
    void registerAllArchitectures();

    /**
     * @brief Factory for creating architecture instances
     *
     * Usage:
     *   ArchitectureFactory::instance().registerArchitecture<STM32F103C8T6>();
     *   auto arch = ArchitectureFactory::instance().create("stm32f103c8t6");
     */
    class ArchitectureFactory
    {
    public:
        using CreatorFunc = std::function<ArchitecturePtr()>;

        // Singleton instance
        static ArchitectureFactory &instance();

        /**
         * @brief Register an architecture type
         * @tparam T Architecture class
         */
        template <typename T>
        void registerArchitecture()
        {
            auto creator = []() -> ArchitecturePtr
            {
                return std::make_shared<T>();
            };

            // Get chip name from temporary instance
            T temp;
            std::string name = temp.getChipName();

            creators_[name] = creator;
        }

        /**
         * @brief Create architecture instance by name
         * @param chip_name Chip identifier (e.g., "stm32f103c8t6")
         * @return Architecture instance or nullptr if not found
         */
        Result<ArchitecturePtr> create(const std::string &chip_name) const;

        /**
         * @brief Check if chip is registered
         */
        bool hasChip(const std::string &chip_name) const;

        /**
         * @brief Get list of available chips
         */
        std::string getAvailableChips() const;

    private:
        ArchitectureFactory();

        void ensureRegistered();

        std::map<std::string, CreatorFunc> creators_;
        bool registered_ = false;
    };
} // namespace Simulator