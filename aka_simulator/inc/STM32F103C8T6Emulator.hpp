// aka_simulator/inc/STM32F103C8T6Emulator.hpp

#pragma once
#include <unicorn/unicorn.h>
#include <elfio/elfio.hpp>
#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <cstdint>

enum class BootMode {
    Flash,
    SystemMemory,
    SRAM
};

/**
 * STM32F103C8T6 Emulator
 * Version 1: Basic emulation with hex instruction logging
 */
class STM32F103C8T6Emulator
{
public:
    STM32F103C8T6Emulator();
    ~STM32F103C8T6Emulator();

    // Main interface
    bool initialize();
    bool loadELF(const std::string &elf_path);
    bool execute(const std::string &log_file_path);
    void cleanup();

    // Utility functions
    void printMemoryLayout() const;
    void printRegisters() const;

private:
    // STM32F103C8T6 Memory Mapping
    // BOOT pins
    static constexpr uint32_t BOOT_BASE = 0x00000000;

    // Flash
    static constexpr uint32_t FLASH_BASE = 0x08000000;
    static constexpr uint32_t FLASH_SIZE = 0x20000; // 128KB - Some might say 64KB, but it depends on the variant
    
    // System memory
    static constexpr uint32_t SYSTEM_MEMORY_BASE = 0x1FFFF000; // System memory for bootloader
    static constexpr uint32_t SYSTEM_MEMORY_SIZE = 0x800;

    // Option bytes
    static constexpr uint32_t OPTION_BYTES_BASE = 0x1FFFF800; // Option bytes
    static constexpr uint32_t OPTION_BYTES_SIZE = 0x400; // min 1 page, infact this must be 0xF

    // SRAM
    static constexpr uint32_t SRAM_BASE = 0x20000000;
    static constexpr uint32_t SRAM_SIZE = 0x00005000; // 20KB

    // Peripheral Region. Found in ARMv7-M Arch Ref Manual
    static constexpr uint32_t BLOCK_SIZE = 0x400; // 1KB block size for peripherals
    
    // APH1 peripherals
    static constexpr uint32_t APH1_TIM2_BASE = 0x40000000;
    static constexpr uint32_t APH1_TIM3_BASE = 0x40000400;
    static constexpr uint32_t APH1_TIM4_BASE = 0x40000800;
    static constexpr uint32_t APH1_RTC_BASE = 0x40002800;
    static constexpr uint32_t APH1_WWDG_BASE = 0x40002C00;
    static constexpr uint32_t APH1_IWDG_BASE = 0x40003000;
    static constexpr uint32_t APH1_SPI2_BASE = 0x40003800;
    static constexpr uint32_t APH1_USART2_BASE = 0x40004400;
    static constexpr uint32_t APH1_USART3_BASE = 0x40004800;
    static constexpr uint32_t APH1_I2C1_BASE = 0x40005400;
    static constexpr uint32_t APH1_I2C2_BASE = 0x40005800;
    static constexpr uint32_t APH1_USB_BASE = 0x40005C00;
    // No mapping for shared USB/CAN SRAM region, this region is used internally by peripheral USB/bxCAN
    static constexpr uint32_t APH1_SHARED_USB_CAN_BASE = 0x40006000; // Shared USB/CAN SRAM region
    static constexpr uint32_t APH1_SHARED_USB_CAN_SIZE = 0x200; // 512 bytes shared SRAM for USB/CAN
    static constexpr uint32_t APH1_bxCAN_BASE = 0x40006400;
    static constexpr uint32_t APH1_BKP_BASE = 0x40006C00;
    static constexpr uint32_t APH1_PWR_BASE = 0x40007000;
    // APH2 peripherals
    static constexpr uint32_t APH2_AFIO_BASE = 0x40010000;
    static constexpr uint32_t APH2_EXTI_BASE = 0x40010400;
    static constexpr uint32_t APH2_GPIOA_BASE = 0x40010800;
    static constexpr uint32_t APH2_GPIOB_BASE = 0x40010C00;
    static constexpr uint32_t APH2_GPIOC_BASE = 0x40011000;
    static constexpr uint32_t APH2_GPIOD_BASE = 0x40011400;
    static constexpr uint32_t APH2_GPIOE_BASE = 0x40011800;
    static constexpr uint32_t APH2_ADC1_BASE = 0x40012400;
    static constexpr uint32_t APH2_ADC2_BASE = 0x40012800;
    static constexpr uint32_t APH2_TIM1_BASE = 0x40012C00;
    static constexpr uint32_t APH2_SPI1_BASE = 0x40013000;
    static constexpr uint32_t APH2_USART1_BASE = 0x40013800;
    // AHB peripherals
    static constexpr uint32_t AHB_DMA_BASE = 0x40020000;
    static constexpr uint32_t AHB_RCC_BASE = 0x40021000;
    static constexpr uint32_t AHB_FLASH_BASE = 0x40022000; // Flash interface
    static constexpr uint32_t AHB_CRC_BASE = 0x40023000;

    // System Control Space (SCS) - found in ARMv7-M Arch Ref Manual
    // There is a larger region that contains SCS, it is 0xE0000000-0x0E010000 or Cortex-M3 internal peripherals
    // But I have not found an official documentation that decribes the exact left regions (except for SCS)
    static constexpr uint32_t SYSTEM_CONTROL_SPACE_BASE = 0xE000E000;
    static constexpr uint32_t SYSTEM_CONTROL_SPACE_SIZE = 0x1000; // 4KB

    // Core components
    uc_engine *uc_engine_;
    std::ofstream log_file_;
    uint32_t entry_point_;
    std::string elf_path_;

    // Hook handles
    uc_hook code_hook_handle_;
    uc_hook invalid_mem_hook_handle_;

    // Boot mode
    BootMode boot_mode_;

    // Private methods
    bool setupMemoryRegions();
    bool loadELFSegments();
    bool setupInitialState();
    bool openLogFile(const std::string &log_file_path);
    void closeLogFile();

    // Callback functions (must be static for C API)
    static void codeHookCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
    static bool invalidMemoryCallback(uc_engine *uc, uc_mem_type type, uint64_t address,
                                      int size, int64_t value, void *user_data);

    // Helper methods for callbacks
    void handleCodeExecution(uint64_t address, uint32_t size);
    void handleInvalidMemory(uint64_t address, int size);

    // Utility methods
    void logHeader();
    void logInstruction(uint64_t address, const uint8_t *instruction_bytes, uint32_t size);
    std::string formatHexBytes(const uint8_t *bytes, uint32_t size) const;
    std::string getCurrentTimestamp() const;

    // Prevent copy and assignment
    STM32F103C8T6Emulator(const STM32F103C8T6Emulator &) = delete;
    STM32F103C8T6Emulator &operator=(const STM32F103C8T6Emulator &) = delete;
};