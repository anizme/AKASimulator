#include "MemoryManager.hpp"
#include "io/utils/StringUtils.hpp"

namespace Simulator
{

    MemoryManager::MemoryManager(uc_engine *uc,
                                 ArchitecturePtr architecture,
                                 LoggerPtr logger)
        : uc_(uc), architecture_(architecture), logger_(logger)
    {

        memory_map_ = architecture_->getMemoryMap();
        boot_descriptor_ = architecture_->getBootDescriptor();
    }

    Result<void> MemoryManager::setupMemoryRegions(BootMode boot_mode)
    {
        LOG_INFO(logger_, "Setting up memory regions...");

        // Map all regions from memory map
        for (const auto &region : memory_map_.getRegions())
        {
            auto result = mapRegion(region);
            if (!result)
            {
                return result;
            }
        }

        // Map boot alias (address 0x00000000)
        auto alias_result = mapBootAlias(boot_mode);
        if (!alias_result)
        {
            return alias_result;
        }

        LOG_INFO(logger_, "Memory setup complete");
        printMemoryLayout();

        return Result<void>::Success();
    }

    Result<void> MemoryManager::mapRegion(const MemoryRegion &region)
    {
        int perm = toUnicornPermission(region.permission);

        LOG_DEBUG_F(logger_) << "Mapping " << region.name
                             << " at " << Utils::formatHex(region.base_address)
                             << " (size: " << (region.size / 1024) << " KB, perm: " << perm << ")";

        uc_err err = uc_mem_map(uc_, region.base_address, region.size, perm);
        if (err != UC_ERR_OK)
        {
            std::string error_msg = "Failed to map " + region.name + ": " + uc_strerror(err);
            LOG_ERROR(logger_, error_msg);
            return Result<void>::Error(error_msg);
        }

        return Result<void>::Success();
    }

    Result<void> MemoryManager::mapBootAlias(BootMode boot_mode)
    {
        LOG_INFO_F(logger_) << "Setting up boot alias for mode: "
                            << static_cast<int>(boot_mode);

        Address boot_alias_base = boot_descriptor_.boot_alias_base;
        Address boot_alias_target = 0;
        Size boot_alias_size = boot_descriptor_.boot_alias_size;

        // Determine boot target based on mode
        switch (boot_mode)
        {
        case BootMode::Flash:
            boot_alias_target = memory_map_.getFlashBase();
            LOG_INFO(logger_, "  Boot from Flash");
            break;

        case BootMode::SRAM:
            boot_alias_target = memory_map_.getSRAMBase();
            LOG_INFO(logger_, "  Boot from SRAM");
            break;

        case BootMode::SystemMemory:
        {
            auto *sys_mem = memory_map_.findRegion("SystemMemory");
            if (sys_mem)
            {
                boot_alias_target = sys_mem->base_address;
                LOG_INFO(logger_, "  Boot from System Memory");
            }
            else
            {
                LOG_WARNING(logger_, "  System Memory not found, defaulting to Flash");
                boot_alias_target = memory_map_.getFlashBase();
            }
            break;
        }
        }

        // Allocate buffer for boot alias
        // In ARM Cortex-M, address 0x00000000 is aliased to Flash/SRAM/SystemMemory
        // We need to use uc_mem_map_ptr to create an alias

        LOG_DEBUG_F(logger_) << "  Boot alias: " << Utils::formatHex(boot_alias_base)
                             << " -> " << Utils::formatHex(boot_alias_target)
                             << " (size: " << (boot_alias_size / 1024) << " KB)";

        // For now, we'll use a simple approach:
        // Map the boot alias region as a separate memory region
        // and copy data from the target after ELF is loaded

        uc_err err = uc_mem_map(uc_, boot_alias_base, boot_alias_size,
                                UC_PROT_READ | UC_PROT_EXEC);
        if (err != UC_ERR_OK)
        {
            std::string error_msg = "Failed to map boot alias: " + std::string(uc_strerror(err));
            LOG_ERROR(logger_, error_msg);
            return Result<void>::Error(error_msg);
        }

        LOG_INFO(logger_, "  ✓ Boot alias mapped");

        return Result<void>::Success();
    }

    int MemoryManager::toUnicornPermission(MemoryPermission perm) const
    {
        int uc_perm = 0;

        if (perm & MemoryPermission::Read)
        {
            uc_perm |= UC_PROT_READ;
        }
        if (perm & MemoryPermission::Write)
        {
            uc_perm |= UC_PROT_WRITE;
        }
        if (perm & MemoryPermission::Execute)
        {
            uc_perm |= UC_PROT_EXEC;
        }

        return uc_perm;
    }

    bool MemoryManager::isValidAddress(Address address) const
    {
        return getRegionForAddress(address) != nullptr;
    }

    const MemoryRegion *MemoryManager::getRegionForAddress(Address address) const
    {
        for (const auto &region : memory_map_.getRegions())
        {
            if (address >= region.base_address &&
                address < region.base_address + region.size)
            {
                return &region;
            }
        }

        // Check boot alias
        Address boot_base = boot_descriptor_.boot_alias_base;
        Size boot_size = boot_descriptor_.boot_alias_size;
        if (address >= boot_base && address < boot_base + boot_size)
        {
            // Return a static region for boot alias
            static MemoryRegion boot_alias_region(
                "BootAlias", boot_base, boot_size,
                MemoryPermission::ReadExecute);
            return &boot_alias_region;
        }

        return nullptr;
    }

    void MemoryManager::printMemoryLayout() const
    {
        LOG_INFO(logger_, "Memory Layout:");

        for (const auto &region : memory_map_.getRegions())
        {
            std::string perm_str;
            if (region.permission & MemoryPermission::Read)
                perm_str += "R";
            if (region.permission & MemoryPermission::Write)
                perm_str += "W";
            if (region.permission & MemoryPermission::Execute)
                perm_str += "X";

            LOG_INFO_F(logger_) << "  " << region.name
                                << ": " << Utils::formatHex(region.base_address)
                                << " - " << Utils::formatHex(region.base_address + region.size - 1)
                                << " (" << (region.size / 1024) << " KB) [" << perm_str << "]";
        }

        // Boot alias
        LOG_INFO_F(logger_) << "  BootAlias: "
                            << Utils::formatHex(boot_descriptor_.boot_alias_base)
                            << " -> "
                            << Utils::formatHex(boot_descriptor_.boot_alias_target);
    }

} // namespace Simulator