// aka_simulator/src/main.cpp

#include "Emulator.hpp"
#include <iostream>
#include <string>
#include <filesystem>

void printUsage(const char *program_name)
{
    std::cout << "Usage: " << program_name << " <elf_file> [log_file]" << std::endl;
    std::cout << " elf_file: Path to STM32F103C8T6 ELF binary" << std::endl;
    std::cout << " log_file: Path to output log file (default: emulation.log)" << std::endl;
    std::cout << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << " " << program_name << " firmware.elf execution.log" << std::endl;
}

int main(int argc, char *argv[])
{
    // ---------------------- Argument handling ----------------------
    if (argc < 3 || argc > 4)
    {
        printUsage(argv[0]);
        return 1;
    }

    std::string elf_file = argv[1];
    std::string stub_file = argv[2];
    std::string log_file = (argc == 4) ? argv[3] : "execution.log";

    std::cout << "=== STM32F103C8T6 Emulator ===" << std::endl;
    std::cout << "ELF File: " << elf_file << std::endl;
    std::cout << "Stub File: " << stub_file << std::endl;
    std::cout << "Log File: " << log_file << std::endl;
    std::cout << std::endl;

    // ---------------------- Emulator initialization ----------------------
    STM32F103C8T6::Emulator emulator;

    if (!emulator.initialize(stub_file))
    {
        std::cerr << "ERROR: Failed to initialize emulator" << std::endl;
        return 1;
    }

    if (!emulator.loadELF(elf_file))
    {
        std::cerr << "ERROR: Failed to load ELF file: " << elf_file << std::endl;
        return 1;
    }

    // Print initial state
    std::cout << std::endl;
    emulator.printRegisters();
    std::cout << std::endl;

    // ---------------------- Execute emulation ----------------------
    std::cout << "Starting emulation (press Ctrl+C to stop)..." << std::endl;
    if (!emulator.execute(log_file))
    {
        std::cerr << "ERROR: Emulation failed" << std::endl;
        return 1;
    }

    // Print final state
    std::cout << std::endl;
    std::cout << "Final state:" << std::endl;
    emulator.printRegisters();
    std::cout << std::endl;
    std::cout << "Emulation completed. Check log file: " << log_file << std::endl;

    return 0;
}