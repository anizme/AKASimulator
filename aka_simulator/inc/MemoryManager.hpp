// aka_simulator/inc/MemoryManager.hpp

#pragma once
#include "MemoryMap.hpp"
#include <unicorn/unicorn.h>

namespace STM32F103C8T6
{

    class MemoryManager
    {
    public:
        explicit MemoryManager(uc_engine *engine, BootMode boot_mode = BootMode::Flash);
        ~MemoryManager() = default;

        bool setupMemoryRegions();
        void printLayout() const;

    private:
        uc_engine *uc_engine_;
        BootMode boot_mode_;

        bool mapBootRegion();
        bool mapCoreMemory();
        bool mapPeripherals();
        bool mapSystemControlSpace();
        bool mapPeripheralBlock(uint32_t base);
        bool mapVirtualStopAddress();
    };

} // namespace STM32F103C8T6
