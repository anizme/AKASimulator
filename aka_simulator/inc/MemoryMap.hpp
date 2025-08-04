// aka_simulator/inc/MemoryMap.hpp

#pragma once
#include <cstdint>

namespace STM32F103C8T6
{

    enum class BootMode
    {
        Flash,
        SystemMemory,
        SRAM
    };

    class MemoryMap
    {
    public:
        // BOOT pins
        static constexpr uint32_t BOOT_BASE = 0x00000000;

        // Flash
        static constexpr uint32_t FLASH_BASE = 0x08000000;
        static constexpr uint32_t FLASH_SIZE = 0x20000; // 128KB - Some might say 64KB, but it depends on the variant

        // System memory
        static constexpr uint32_t SYSTEM_MEMORY_BASE = 0x1FFFF000;
        static constexpr uint32_t SYSTEM_MEMORY_SIZE = 0x800;

        // Option bytes
        static constexpr uint32_t OPTION_BYTES_BASE = 0x1FFFF800;
        static constexpr uint32_t OPTION_BYTES_SIZE = 0x400; // 1 page is the minimum, in fact this must be 0xF

        // SRAM
        static constexpr uint32_t SRAM_BASE = 0x20000000;
        static constexpr uint32_t SRAM_SIZE = 0x00005000; // 20KB

        // Peripheral Region. Found in ARMv7-M Arch Ref Manual
        static constexpr uint32_t BLOCK_SIZE = 0x400; // 1KB block size

        // APB1 peripherals
        static constexpr uint32_t APB1_TIM2_BASE = 0x40000000;
        static constexpr uint32_t APB1_TIM3_BASE = 0x40000400;
        static constexpr uint32_t APB1_TIM4_BASE = 0x40000800;
        static constexpr uint32_t APB1_RTC_BASE = 0x40002800;
        static constexpr uint32_t APB1_WWDG_BASE = 0x40002C00;
        static constexpr uint32_t APB1_IWDG_BASE = 0x40003000;
        static constexpr uint32_t APB1_SPI2_BASE = 0x40003800;
        static constexpr uint32_t APB1_USART2_BASE = 0x40004400;
        static constexpr uint32_t APB1_USART3_BASE = 0x40004800;
        static constexpr uint32_t APB1_I2C1_BASE = 0x40005400;
        static constexpr uint32_t APB1_I2C2_BASE = 0x40005800;
        static constexpr uint32_t APB1_USB_BASE = 0x40005C00;
        // No mapping for shared USB/CAN SRAM region, this region is used internally by peripheral USB/bxCAN
        static constexpr uint32_t APB1_SHARED_USB_CAN_BASE = 0x40006000;
        static constexpr uint32_t APB1_SHARED_USB_CAN_SIZE = 0x200;
        static constexpr uint32_t APB1_bxCAN_BASE = 0x40006400;
        static constexpr uint32_t APB1_BKP_BASE = 0x40006C00;
        static constexpr uint32_t APB1_PWR_BASE = 0x40007000;

        // APB2 peripherals
        static constexpr uint32_t APB2_AFIO_BASE = 0x40010000;
        static constexpr uint32_t APB2_EXTI_BASE = 0x40010400;
        static constexpr uint32_t APB2_GPIOA_BASE = 0x40010800;
        static constexpr uint32_t APB2_GPIOB_BASE = 0x40010C00;
        static constexpr uint32_t APB2_GPIOC_BASE = 0x40011000;
        static constexpr uint32_t APB2_GPIOD_BASE = 0x40011400;
        static constexpr uint32_t APB2_GPIOE_BASE = 0x40011800;
        static constexpr uint32_t APB2_ADC1_BASE = 0x40012400;
        static constexpr uint32_t APB2_ADC2_BASE = 0x40012800;
        static constexpr uint32_t APB2_TIM1_BASE = 0x40012C00;
        static constexpr uint32_t APB2_SPI1_BASE = 0x40013000;
        static constexpr uint32_t APB2_USART1_BASE = 0x40013800;

        // AHB peripherals
        static constexpr uint32_t AHB_DMA_BASE = 0x40020000;
        static constexpr uint32_t AHB_RCC_BASE = 0x40021000;
        static constexpr uint32_t AHB_FLASH_BASE = 0x40022000;
        static constexpr uint32_t AHB_CRC_BASE = 0x40023000;

        // System Control Space (SCS) - found in ARMv7-M Arch Ref Manual
        // There is a larger region that contains SCS, it is 0xE0000000-0x0E010000 or Cortex-M3 internal peripherals
        // But I have not found an official documentation that decribes the exact left regions (except for SCS)
        static constexpr uint32_t SYSTEM_CONTROL_SPACE_BASE = 0xE000E000;
        static constexpr uint32_t SYSTEM_CONTROL_SPACE_SIZE = 0x1000;

        // Stop address for main function return
        // Currently, boot mode is not used, so I pick an reserved address
        // to make the stop address (return address for main function - this is test driver's main function)
        static constexpr uint32_t STOP_ADDR = 0x08020000;

        static void printLayout();
    };

} // namespace STM32F103C8T6