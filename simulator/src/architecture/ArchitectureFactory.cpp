#include "ArchitectureFactory.hpp"

namespace Simulator
{
    void registerAllArchitectures()
    {
        auto &factory = ArchitectureFactory::instance();

        // Register ARM Cortex-M chips
        factory.registerArchitecture<ARM::STM32F103C8T6>();
        factory.registerArchitecture<ARM::STM32F407VG>();

        // Add more chips here as needed...
    }

    ArchitectureFactory::ArchitectureFactory() = default;

    ArchitectureFactory &ArchitectureFactory::instance()
    {
        static ArchitectureFactory factory;
        static bool initialized = false;
        if (!initialized)
        {
            initialized = true;
            factory.ensureRegistered();
        }
        return factory;
    }

    void ArchitectureFactory::ensureRegistered()
    {
        if (!registered_)
        {
            registerAllArchitectures();
            registered_ = true;
        }
    }

    Result<ArchitecturePtr> ArchitectureFactory::create(const std::string &chip_name) const
    {
        auto it = creators_.find(chip_name);
        if (it == creators_.end())
        {
            return Result<ArchitecturePtr>::Error(
                "Unknown chip: " + chip_name + ". Available: " + getAvailableChips());
        }

        return Result<ArchitecturePtr>::Success(it->second());
    }

    bool ArchitectureFactory::hasChip(const std::string &chip_name) const
    {
        return creators_.find(chip_name) != creators_.end();
    }

    std::string ArchitectureFactory::getAvailableChips() const
    {
        std::string result;
        for (const auto &pair : creators_)
        {
            if (!result.empty())
                result += ", ";
            result += pair.first;
        }
        return result;
    }

} // namespace Simulator
