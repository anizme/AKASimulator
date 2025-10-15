// aka_simulator/src/main.cpp

#include "Emulator.hpp"
#include "SimulationLogRefactor.hpp"
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
    if (argc < 2 || argc > 3)
    {
        printUsage(argv[0]);
        return 1;
    }

    std::string elf_file = argv[1];
    std::string log_file = (argc == 3) ? argv[2] : "execution.log";

    std::cout << "=== STM32F103C8T6 Emulator ===" << std::endl;
    std::cout << "ELF File: " << elf_file << std::endl;
    std::cout << "Log File: " << log_file << std::endl;
    std::cout << std::endl;

    // ---------------------- Emulator initialization ----------------------
    STM32F103C8T6::Emulator emulator;

    if (!emulator.initialize())
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

    // ---------------------- Post-process log ----------------------
    std::cout << std::endl;
    std::cout << "=== Post-processing log file ===" << std::endl;

    namespace fs = std::filesystem;

    // Get base name and directory
    fs::path logPath(log_file);
    fs::path dir = logPath.parent_path();
    std::string baseName = logPath.stem().string(); // "name" if file is ".../name.log"

    // Input for refactor: code_line_name.log
    std::string codeLineLog = (dir / ("code_line_" + baseName + ".log")).string();

    // Output after refactor: simu_name.log
    std::string refactoredBase = (dir / ("simu_" + baseName)).string();

    SimulationLogRefactor refactor(codeLineLog);

    if (refactor.process(refactoredBase))
    {
        std::cout << "Log refactoring completed successfully!" << std::endl;
        std::cout << "Output: " << refactoredBase << "_simulation.log" << std::endl;
    }
    else
    {
        std::cerr << "Log refactoring failed!" << std::endl;
        std::cerr << "Expected input: " << codeLineLog << std::endl;
        return 1;
    }

    return 0;
}