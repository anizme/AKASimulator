#pragma once

#include "../ARMCortexM3.hpp"

namespace Simulator
{
    namespace ARM
    {

        /**
         * @brief STM32F103C8T6 chip definition
         *
         * Specs:
         * - ARM Cortex-M3 @ 72MHz
         * - 64KB Flash
         * - 20KB SRAM
         * - Medium-density device
         */
        class STM32F103C8T6 : public ARMCortexM3Base
        {
        public:
            std::string getChipName() const override
            {
                return "stm32f103c8t6";
            }

            std::string getDescription() const override
            {
                return "STM32F103C8T6";
            }

            MemoryMapDescriptor getMemoryMap() const override
            {
                MemoryMapDescriptor map;

                // Flash memory
                map.addFlash(0x08000000, 128 * 1024); // 128KB - Some might say 64KB, but it depends on the variant

                // SRAM
                map.addSRAM(0x20000000, 20 * 1024); // 20KB

                // System memory (bootloader)
                map.addRegion(MemoryRegion(
                    "SystemMemory", 0x1FFFF000, 2 * 1024,
                    MemoryPermission::ReadExecute));

                // Option bytes
                map.addRegion(MemoryRegion(
                    "OptionBytes", 0x1FFFF800, 1024 /*1 page is the minimum, in fact this must be 0xF*/,
                    MemoryPermission::Read));

                // Peripherals - APB1
                map.addPeripheral("APB1_TIM2", 0x40000000, 0x400);
                map.addPeripheral("APB1_TIM3", 0x40000400, 0x400);
                map.addPeripheral("APB1_TIM4", 0x40000800, 0x400);
                map.addPeripheral("APB1_RTC", 0x40002800, 0x400);
                map.addPeripheral("APB1_WWDG", 0x40002C00, 0x400);
                map.addPeripheral("APB1_IWDG", 0x40003000, 0x400);
                map.addPeripheral("APB1_SPI2", 0x40003800, 0x400);
                map.addPeripheral("APB1_USART2", 0x40004400, 0x400);
                map.addPeripheral("APB1_USART3", 0x40004800, 0x400);
                map.addPeripheral("APB1_I2C1", 0x40005400, 0x400);
                map.addPeripheral("APB1_I2C2", 0x40005800, 0x400);
                map.addPeripheral("APB1_USB", 0x40005C00, 0x400);
                map.addPeripheral("APB1_CAN", 0x40006400, 0x400);
                map.addPeripheral("APB1_BKP", 0x40006C00, 0x400);
                map.addPeripheral("APB1_PWR", 0x40007000, 0x400);

                // Peripherals - APB2
                map.addPeripheral("APB2_AFIO", 0x40010000, 0x400);
                map.addPeripheral("APB2_EXTI", 0x40010400, 0x400);
                map.addPeripheral("APB2_GPIOA", 0x40010800, 0x400);
                map.addPeripheral("APB2_GPIOB", 0x40010C00, 0x400);
                map.addPeripheral("APB2_GPIOC", 0x40011000, 0x400);
                map.addPeripheral("APB2_GPIOD", 0x40011400, 0x400);
                map.addPeripheral("APB2_GPIOE", 0x40011800, 0x400);
                map.addPeripheral("APB2_ADC1", 0x40012400, 0x400);
                map.addPeripheral("APB2_ADC2", 0x40012800, 0x400);
                map.addPeripheral("APB2_TIM1", 0x40012C00, 0x400);
                map.addPeripheral("APB2_SPI1", 0x40013000, 0x400);
                map.addPeripheral("APB2_USART1", 0x40013800, 0x400);

                // Peripherals - AHB
                map.addPeripheral("AHB_DMA1", 0x40020000, 0x400);
                map.addPeripheral("AHB_RCC", 0x40021000, 0x400);
                map.addPeripheral("AHB_FLASH", 0x40022000, 0x400);
                map.addPeripheral("AHB_CRC", 0x40023000, 0x400);

                // Cortex-M3 system control space
                map.addPeripheral("NVIC", 0xE000E000, 0x1000);

                return map;
            }

            BootDescriptor getBootDescriptor() const override
            {
                BootDescriptor boot = ARMCortexM3Base::getBootDescriptor();

                // Vector table in Flash
                boot.vector_table_address = 0x08000000;
                boot.vector_table_size = 0x150; // 16 + 68 interrupts

                // Boot alias points to Flash
                boot.boot_alias_target = 0x08000000;
                // boot.boot_alias_size = 128 * 1024; 
                // Equal to Flash size, but if so, it would overlap with SRAM. This should be implemented by uc_mem_map_ptr

                return boot;
            }
        };

    } // namespace ARM
} // namespace Simulator