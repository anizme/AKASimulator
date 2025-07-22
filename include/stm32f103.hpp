// include/stm32f103.hpp

#pragma once
#include <cstdint>

namespace STM32F103 {

    // Flash memory
    namespace FLASH {
        constexpr uint32_t BASE = 0x08000000;
        constexpr uint32_t SIZE = 128 * 1024; // 128KB
    }

    // RAM memory
    namespace RAM {
        constexpr uint32_t BASE = 0x20000000;
        constexpr uint32_t SIZE = 20 * 1024; // 20KB
    }

    // Peripheral base addresses
    namespace PERIPHERALS {

        // RCC - Reset and Clock Control
        namespace RCC {
            constexpr uint32_t BASE  = 0x40021000;
            constexpr uint32_t CR    = BASE + 0x00;
            constexpr uint32_t CFGR  = BASE + 0x04;
            constexpr uint32_t APB2ENR = BASE + 0x18;
        }

        // GPIOA
        namespace GPIOA {
            constexpr uint32_t BASE = 0x40010800;
            constexpr uint32_t CRL  = BASE + 0x00;
            constexpr uint32_t CRH  = BASE + 0x04;
            constexpr uint32_t IDR  = BASE + 0x08;
            constexpr uint32_t ODR  = BASE + 0x0C;
            constexpr uint32_t BSRR = BASE + 0x10;
            constexpr uint32_t BRR  = BASE + 0x14;
        }

        // GPIOB
        namespace GPIOB {
            constexpr uint32_t BASE = 0x40010C00;
            constexpr uint32_t CRL  = BASE + 0x00;
            constexpr uint32_t CRH  = BASE + 0x04;
            constexpr uint32_t IDR  = BASE + 0x08;
            constexpr uint32_t ODR  = BASE + 0x0C;
            constexpr uint32_t BSRR = BASE + 0x10;
            constexpr uint32_t BRR  = BASE + 0x14;
        }

        // USART1
        namespace USART1 {
            constexpr uint32_t BASE  = 0x40013800;
            constexpr uint32_t SR    = BASE + 0x00;
            constexpr uint32_t DR    = BASE + 0x04;
            constexpr uint32_t BRR   = BASE + 0x08;
            constexpr uint32_t CR1   = BASE + 0x0C;
            constexpr uint32_t CR2   = BASE + 0x10;
            constexpr uint32_t CR3   = BASE + 0x14;
        }

        // TIM2 - Basic Timer
        namespace TIM2 {
            constexpr uint32_t BASE  = 0x40000000;
            constexpr uint32_t CR1   = BASE + 0x00;
            constexpr uint32_t CNT   = BASE + 0x24;
            constexpr uint32_t PSC   = BASE + 0x28;
            constexpr uint32_t ARR   = BASE + 0x2C;
        }

        // SysTick (in Cortex-M3 system control space)
        namespace SYSTICK {
            constexpr uint32_t BASE    = 0xE000E010;
            constexpr uint32_t CTRL    = BASE + 0x00;
            constexpr uint32_t LOAD    = BASE + 0x04;
            constexpr uint32_t VAL     = BASE + 0x08;
            constexpr uint32_t CALIB   = BASE + 0x0C;
        }

        // NVIC - Nested Vector Interrupt Controller
        namespace NVIC {
            constexpr uint32_t ISER0   = 0xE000E100;
            constexpr uint32_t ICER0   = 0xE000E180;
            constexpr uint32_t ISPR0   = 0xE000E200;
            constexpr uint32_t ICPR0   = 0xE000E280;
            constexpr uint32_t IPR_BASE = 0xE000E400; // Interrupt Priority Registers
        }
    }

}
