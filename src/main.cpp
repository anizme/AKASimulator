// src/main.cpp

#include "simulator.hpp"
#include "elf_loader.hpp"
#include "stm32f103.hpp"
#include <iostream>
#include <memory>

class PeripheralHooks {
public:
    static void register_all(Simulator& sim) {
        // GPIO Hooks
        register_gpio_hooks(sim);
        
        // RCC Hooks
        register_rcc_hooks(sim);
        
        // System Hooks
        register_system_hooks(sim);
        
        // NVIC Hooks
        register_nvic_hooks(sim);
    }

private:
    static void register_gpio_hooks(Simulator& sim) {
        using namespace STM32F103::PERIPHERALS;
        
        auto gpio_hook = [](const char* port, uc_engine*, uint64_t addr, int, int64_t value) {
            std::cout << "[" << port << "] Write ODR @ 0x" 
                      << std::hex << addr << " = 0x" << value;
            
            if (port[4] == 'C') {  // Only for GPIOC
                std::cout << " | PC13 state: " << ((value & (1 << 13)) ? "ON" : "OFF");
            }
            std::cout << std::endl;
        };

        sim.add_mem_write_hook(GPIOA::ODR, GPIOA::ODR + 4, 
            std::bind(gpio_hook, "GPIOA", std::placeholders::_1, std::placeholders::_2, 
                      std::placeholders::_3, std::placeholders::_4));

        sim.add_mem_write_hook(GPIOB::ODR, GPIOB::ODR + 4,
            std::bind(gpio_hook, "GPIOB", std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4));

        sim.add_mem_write_hook(GPIOC::ODR, GPIOC::ODR + 4,
            std::bind(gpio_hook, "GPIOC", std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4));
    }

    static void register_rcc_hooks(Simulator& sim) {
        using namespace STM32F103::PERIPHERALS;
        
        auto rcc_hook = [](const char* reg, uc_engine*, uint64_t addr, int, int64_t value) {
            std::cout << "[RCC] Write " << reg << " @ 0x" 
                      << std::hex << addr << " = 0x" << value << std::endl;
        };

        sim.add_mem_write_hook(RCC::CR, RCC::CR + 4,
            std::bind(rcc_hook, "CR", std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4));

        sim.add_mem_write_hook(RCC::APB2ENR, RCC::APB2ENR + 4,
            std::bind(rcc_hook, "APB2ENR", std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4));
    }

    static void register_system_hooks(Simulator& sim) {
        using namespace STM32F103::PERIPHERALS;
        
        sim.add_mem_write_hook(SYSTICK::CTRL, SYSTICK::CTRL + 4,
            [](uc_engine*, uint64_t addr, int, int64_t value) {
                std::cout << "[SysTick] Write CTRL @ 0x" 
                          << std::hex << addr << " = 0x" << value << std::endl;
            });
    }

    static void register_nvic_hooks(Simulator& sim) {
        using namespace STM32F103::PERIPHERALS;
        
        auto nvic_hook = [](const char* reg, uc_engine*, uint64_t addr, int, int64_t value) {
            std::cout << "[NVIC] Write " << reg << " @ 0x" 
                      << std::hex << addr << " = 0x" << value << std::endl;
        };

        const std::vector<std::pair<uint32_t, const char*>> nvic_registers = {
            {NVIC::ISER0, "ISER0"},
            {NVIC::ICER0, "ICER0"},
            {NVIC::ISPR0, "ISPR0"},
            {NVIC::ICPR0, "ICPR0"}
        };

        for (const auto& [addr, name] : nvic_registers) {
            sim.add_mem_write_hook(addr, addr + 4,
                std::bind(nvic_hook, name, std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3, std::placeholders::_4));
        }

        // IPR range
        sim.add_mem_write_hook(NVIC::IPR_BASE, NVIC::IPR_BASE + 0x100,
            [](uc_engine*, uint64_t addr, int, int64_t value) {
                std::cout << "[NVIC] Write IPR @ 0x" 
                          << std::hex << addr << " = 0x" << value << std::endl;
            });
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <elf_file>" << std::endl;
        return 1;
    }

    try {
        // Load ELF segments
        ElfLoader loader;
        if (!loader.load(argv[1])) {
            std::cerr << "Failed to load ELF file: " << argv[1] << std::endl;
            return 1;
        }

        // Initialize simulator
        Simulator sim(
            STM32F103::FLASH::BASE, STM32F103::FLASH::SIZE,
            STM32F103::RAM::BASE, STM32F103::RAM::SIZE);

        // Load all loadable segments
        for (const auto& seg : loader.get_segments()) {
            if (!sim.load_code(seg.physical_address, seg.data)) {
                std::cerr << "Failed to load segment at 0x" 
                          << std::hex << seg.physical_address << std::endl;
                return 1;
            }
        }

        // Register all hooks
        PeripheralHooks::register_all(sim);

        // Start simulation
        std::cout << "Starting simulation at 0x" 
                  << std::hex << loader.get_entry_point() << std::endl;
        sim.run(loader.get_entry_point());

        // Print some register values
        std::cout << "\nSimulation finished. Register values:" << std::endl;
        for (int i = 0; i <= 12; ++i) {
            std::cout << "R" << i << " = 0x" 
                      << std::hex << sim.read_register(UC_ARM_REG_R0 + i) << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}