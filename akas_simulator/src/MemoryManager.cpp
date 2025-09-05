// aka_simulator/src/MemoryManager.cpp

#include "MemoryManager.hpp"
#include <iostream>
#include <vector>

namespace STM32F103C8T6
{

    MemoryManager::MemoryManager(uc_engine *engine, BootMode boot_mode)
        : uc_engine_(engine), boot_mode_(boot_mode)
    {
    }

    bool MemoryManager::setupMemoryRegions()
    {
        std::cout << "[Setup] Memory regions..." << std::endl;
        if (!mapBootRegion())
        {
            std::cerr << "Failed to map boot region" << std::endl;
            return false;
        }

        if (!mapCoreMemory())
        {
            std::cerr << "Failed to map core memory regions" << std::endl;
            return false;
        }

        if (!mapPeripherals())
        {
            std::cerr << "Failed to map peripheral regions" << std::endl;
            return false;
        }

        if (!mapSystemControlSpace())
        {
            std::cerr << "Failed to map system control space" << std::endl;
            return false;
        }

        return true;
    }

    bool MemoryManager::mapBootRegion()
    {
        std::cout << "[Setup] Boot region..." << std::endl;
        uc_err err;

        // Boot region mapping based on boot mode
        if (boot_mode_ == BootMode::Flash)
        {
            err = uc_mem_map_ptr(uc_engine_, MemoryMap::BOOT_BASE, MemoryMap::FLASH_SIZE, UC_PROT_READ | UC_PROT_EXEC, MemoryMap::flash_buf);
            if (err != UC_ERR_OK)
            {
                std::cerr << "Failed to map BOOT alias region (Flash mode): " << uc_strerror(err) << std::endl;
                return false;
            }
        }
        else if (boot_mode_ == BootMode::SRAM)
        {
            std::cerr << "SRAM boot mode has not been supported yet" << std::endl;
            return false;
        }
        else
        {
            std::cerr << "System Memory boot mode has not been supported yet" << std::endl;
            return false;
        }

        return true;
    }

    bool MemoryManager::mapCoreMemory()
    {
        std::cout << "[Setup] Core memory regions..." << std::endl;
        uc_err err;

        // Map Flash memory (readable + executable)
        err = uc_mem_map_ptr(uc_engine_, MemoryMap::FLASH_BASE, MemoryMap::FLASH_SIZE, UC_PROT_READ | UC_PROT_EXEC, MemoryMap::flash_buf);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to map Flash memory: " << uc_strerror(err) << std::endl;
            return false;
        }

        // System Memory
        err = uc_mem_map(uc_engine_, MemoryMap::SYSTEM_MEMORY_BASE, MemoryMap::SYSTEM_MEMORY_SIZE, UC_PROT_READ | UC_PROT_EXEC);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to map System Memory: " << uc_strerror(err) << std::endl;
            return false;
        }

        // Option Bytes
        err = uc_mem_map(uc_engine_, MemoryMap::OPTION_BYTES_BASE, MemoryMap::OPTION_BYTES_SIZE, UC_PROT_READ);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to map Option Bytes: " << uc_strerror(err) << std::endl;
            return false;
        }

        // Map SRAM (readable + writable)
        err = uc_mem_map(uc_engine_, MemoryMap::SRAM_BASE, MemoryMap::SRAM_SIZE, UC_PROT_READ | UC_PROT_WRITE);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to map SRAM: " << uc_strerror(err) << std::endl;
            return false;
        }

        return true;
    }

    bool MemoryManager::mapPeripherals()
    {
        std::cout << "[Setup] Peripheral regions..." << std::endl;
        // APB1 peripherals
        const std::vector<uint32_t> apb1_bases = {
            MemoryMap::APB1_TIM2_BASE, MemoryMap::APB1_TIM3_BASE, MemoryMap::APB1_TIM4_BASE,
            MemoryMap::APB1_RTC_BASE, MemoryMap::APB1_WWDG_BASE, MemoryMap::APB1_IWDG_BASE,
            MemoryMap::APB1_SPI2_BASE, MemoryMap::APB1_USART2_BASE, MemoryMap::APB1_USART3_BASE,
            MemoryMap::APB1_I2C1_BASE, MemoryMap::APB1_I2C2_BASE, MemoryMap::APB1_USB_BASE,
            MemoryMap::APB1_bxCAN_BASE, MemoryMap::APB1_BKP_BASE, MemoryMap::APB1_PWR_BASE};

        for (auto base : apb1_bases)
        {
            if (!mapPeripheralBlock(base))
            {
                return false;
            }
        }

        // APB2 peripherals
        const std::vector<uint32_t> apb2_bases = {
            MemoryMap::APB2_AFIO_BASE, MemoryMap::APB2_EXTI_BASE, MemoryMap::APB2_GPIOA_BASE,
            MemoryMap::APB2_GPIOB_BASE, MemoryMap::APB2_GPIOC_BASE, MemoryMap::APB2_GPIOD_BASE,
            MemoryMap::APB2_GPIOE_BASE, MemoryMap::APB2_ADC1_BASE, MemoryMap::APB2_ADC2_BASE,
            MemoryMap::APB2_TIM1_BASE, MemoryMap::APB2_SPI1_BASE, MemoryMap::APB2_USART1_BASE};

        for (auto base : apb2_bases)
        {
            if (!mapPeripheralBlock(base))
            {
                return false;
            }
        }

        // AHB peripherals
        const std::vector<uint32_t> ahb_bases = {
            MemoryMap::AHB_DMA_BASE, MemoryMap::AHB_RCC_BASE,
            MemoryMap::AHB_FLASH_BASE, MemoryMap::AHB_CRC_BASE};

        for (auto base : ahb_bases)
        {
            if (!mapPeripheralBlock(base))
            {
                return false;
            }
        }

        return true;
    }

    bool MemoryManager::mapSystemControlSpace()
    {
        std::cout << "[Setup] System Control Space..." << std::endl;
        uc_err err = uc_mem_map(uc_engine_, MemoryMap::SYSTEM_CONTROL_SPACE_BASE,
                                MemoryMap::SYSTEM_CONTROL_SPACE_SIZE, UC_PROT_READ | UC_PROT_WRITE);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to map System Control Space: " << uc_strerror(err) << std::endl;
            return false;
        }
        return true;
    }

    bool MemoryManager::mapPeripheralBlock(uint32_t base)
    {
        uc_err err = uc_mem_map(uc_engine_, base, MemoryMap::BLOCK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
        if (err != UC_ERR_OK)
        {
            std::cerr << "Failed to map peripheral block at 0x" << std::hex << base
                      << ": " << uc_strerror(err) << std::endl;
            return false;
        }
        return true;
    }

    void MemoryManager::printLayout() const
    {
        MemoryMap::printLayout();
    }

} // namespace STM32F103C8T6