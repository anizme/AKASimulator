// src/main.cpp

#include "simulator.hpp"
#include "elf_loader.hpp"
#include "stm32f103.hpp"
#include <iostream>

void add_basic_hooks(Simulator &sim)
{
    using namespace STM32F103::PERIPHERALS;

    // GPIOA
    sim.add_mem_write_hook(GPIOA::ODR, GPIOA::ODR + 4,
                           [](uc_engine *, uint64_t addr, int size, int64_t value)
                           {
                               std::cout << "[GPIOA] Write ODR @ 0x" << std::hex << addr << " = 0x" << value << std::endl;
                           });

    // GPIOB
    sim.add_mem_write_hook(GPIOB::ODR, GPIOB::ODR + 4,
                           [](uc_engine *, uint64_t addr, int size, int64_t value)
                           {
                               std::cout << "[GPIOB] Write ODR @ 0x" << std::hex << addr << " = 0x" << value << std::endl;
                           });

    // GPIOC
    sim.add_mem_write_hook(GPIOC::ODR, GPIOC::ODR + 4,
                           [](uc_engine *, uint64_t addr, int size, int64_t value)
                           {
                               std::cout << "[GPIOC] Write ODR @ 0x" << std::hex << addr
                                         << " = 0x" << value
                                         << " | PC13 state: " << ((value & (1 << 13)) ? "ON" : "OFF")
                                         << std::endl;
                           });

    

    // RCC
    sim.add_mem_write_hook(RCC::CR, RCC::CR + 4,
                           [](uc_engine *, uint64_t addr, int size, int64_t value)
                           {
                               std::cout << "[RCC] Write CR @ 0x" << std::hex << addr << " = 0x" << value << std::endl;
                           });

    sim.add_mem_write_hook(RCC::APB2ENR, RCC::APB2ENR + 4,
                           [](uc_engine *, uint64_t addr, int size, int64_t value)
                           {
                               std::cout << "[RCC] Write APB2ENR @ 0x" << std::hex << addr << " = 0x" << value << std::endl;
                           });

    // SYSTICK
    sim.add_mem_write_hook(SYSTICK::CTRL, SYSTICK::CTRL + 4,
                           [](uc_engine *, uint64_t addr, int size, int64_t value)
                           {
                               std::cout << "[SysTick] Write CTRL @ 0x" << std::hex << addr << " = 0x" << value << std::endl;
                           });

    // NVIC
    // NVIC ISER0
    sim.add_mem_write_hook(NVIC::ISER0, NVIC::ISER0 + 4, [](uc_engine *, uint64_t addr, int size, int64_t value)
                           { std::cout << "[NVIC] Write ISER0 @ 0x" << std::hex << addr << " = 0x" << value << std::endl; });

    // NVIC ICER0
    sim.add_mem_write_hook(NVIC::ICER0, NVIC::ICER0 + 4, [](uc_engine *, uint64_t addr, int size, int64_t value)
                           { std::cout << "[NVIC] Write ICER0 @ 0x" << std::hex << addr << " = 0x" << value << std::endl; });

    // NVIC ISPR0
    sim.add_mem_write_hook(NVIC::ISPR0, NVIC::ISPR0 + 4, [](uc_engine *, uint64_t addr, int size, int64_t value)
                           { std::cout << "[NVIC] Write ISPR0 @ 0x" << std::hex << addr << " = 0x" << value << std::endl; });

    // NVIC ICPR0
    sim.add_mem_write_hook(NVIC::ICPR0, NVIC::ICPR0 + 4, [](uc_engine *, uint64_t addr, int size, int64_t value)
                           { std::cout << "[NVIC] Write ICPR0 @ 0x" << std::hex << addr << " = 0x" << value << std::endl; });

    // Optionally: IPR
    sim.add_mem_write_hook(NVIC::IPR_BASE, NVIC::IPR_BASE + 0x100, [](uc_engine *, uint64_t addr, int size, int64_t value)
                           { std::cout << "[NVIC] Write IPR @ 0x" << std::hex << addr << " = 0x" << value << std::endl; });

}

int main()
{
    try
    {
        ElfLoader loader;
        if (!loader.load("elf_builder/input_source/main.elf"))
        {
            std::cerr << "Failed to load ELF!" << std::endl;
            return 1;
        }

        Simulator sim(
            STM32F103::FLASH::BASE, STM32F103::FLASH::SIZE,
            STM32F103::RAM::BASE, STM32F103::RAM::SIZE);

        for (const auto &section : loader.get_segments())
        {
            sim.load_code(section.physical_address, section.data);
        }

        add_basic_hooks(sim);

        sim.run(loader.get_entry_point());

        std::cout << "R0 = 0x" << std::hex << sim.read_register(UC_ARM_REG_R0) << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
