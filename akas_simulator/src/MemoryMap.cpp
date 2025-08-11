#include "MemoryMap.hpp"
#include <iostream>
#include <iomanip>

namespace STM32F103C8T6
{

    void MemoryMap::printLayout()
    {
        std::cout << "Memory Layout:" << std::endl;
        std::cout << "\tFlash: 0x" << std::hex << FLASH_BASE << " - 0x"
                  << (FLASH_BASE + FLASH_SIZE - 1) << " (" << std::dec << (FLASH_SIZE / 1024) << "KB)" << std::endl;
        std::cout << "\tSRAM:  0x" << std::hex << SRAM_BASE << " - 0x"
                  << (SRAM_BASE + SRAM_SIZE - 1) << " (" << std::dec << (SRAM_SIZE / 1024) << "KB)" << std::endl;
        std::cout << "\tSystem Memory: 0x" << std::hex << SYSTEM_MEMORY_BASE << " - 0x"
                  << (SYSTEM_MEMORY_BASE + SYSTEM_MEMORY_SIZE - 1) << std::endl;
        std::cout << "\tOption Bytes: 0x" << OPTION_BYTES_BASE << " - 0x"
                  << (OPTION_BYTES_BASE + OPTION_BYTES_SIZE - 1) << std::endl;
        std::cout << "\tSystem Control Space: 0x" << SYSTEM_CONTROL_SPACE_BASE << " - 0x"
                  << (SYSTEM_CONTROL_SPACE_BASE + SYSTEM_CONTROL_SPACE_SIZE - 1) << std::dec << std::endl;
    }

} // namespace STM32F103C8T6