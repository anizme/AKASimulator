#include "AKASimulator.hpp"
#include <iostream>
#include <cstring>

void printUsage(const char *program_name)
{
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Required options:\n";
    std::cout << "  --chip <name>        Target chip (e.g., stm32f103c8t6)\n";
    std::cout << "  --elf <file>         ELF binary file\n\n";
    std::cout << "Optional options:\n";
    std::cout << "  --stub <file>        Stub definitions file\n";
    std::cout << "  --log <file>         Execution log output (default: execution.log)\n";
    std::cout << "  --trace <file>       Trace file output (default: trace.trc)\n";
    std::cout << "  --testpath <file>    Test path output (default: testpath.tp)\n";
    std::cout << "  --boot <mode>        Boot mode: flash|sram|system (default: flash)\n";
    std::cout << "  --limit <count>      Instruction limit (default: 100000, 0=unlimited)\n";
    std::cout << "  --timeout <ms>       Timeout in milliseconds (default: 10000)\n";
    std::cout << "  --no-trace           Disable instruction tracing\n";
    std::cout << "  --no-error-detect    Disable error detection\n";
    std::cout << "  --verbose            Verbose output\n";
    std::cout << "  --help               Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " --chip stm32f103c8t6 --elf firmware.elf\n";
    std::cout << "  " << program_name << " --chip stm32f103c8t6 --elf firmware.elf --stub stubs.txt\n";
    std::cout << "  " << program_name << " --chip stm32f407vg --elf firmware.elf --verbose\n\n";
}

int main(int argc, char *argv[])
{
    using namespace Simulator;

    // Parse command line arguments
    SimulatorConfig config;
    config.log_file = "execution.log";
    config.trace_file = "trace.trc";
    config.testpath_file = "testpath.tp";

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h")
        {
            printUsage(argv[0]);
            return 0;
        }
        else if (arg == "--chip" && i + 1 < argc)
        {
            config.chip_name = argv[++i];
        }
        else if (arg == "--elf" && i + 1 < argc)
        {
            config.elf_file = argv[++i];
        }
        else if (arg == "--stub" && i + 1 < argc)
        {
            config.stub_file = argv[++i];
        }
        else if (arg == "--log" && i + 1 < argc)
        {
            config.log_file = argv[++i];
        }
        else if (arg == "--trace" && i + 1 < argc)
        {
            config.trace_file = argv[++i];
        }
        else if (arg == "--testpath" && i + 1 < argc)
        {
            config.testpath_file = argv[++i];
        }
        else if (arg == "--boot" && i + 1 < argc)
        {
            std::string mode = argv[++i];
            if (mode == "flash")
            {
                config.boot_mode = BootMode::Flash;
            }
            else if (mode == "sram")
            {
                config.boot_mode = BootMode::SRAM;
            }
            else if (mode == "system")
            {
                config.boot_mode = BootMode::SystemMemory;
            }
            else
            {
                std::cerr << "Error: Invalid boot mode: " << mode << std::endl;
                return 1;
            }
        }
        else if (arg == "--limit" && i + 1 < argc)
        {
            config.instruction_limit = std::stoull(argv[++i]);
        }
        else if (arg == "--timeout" && i + 1 < argc)
        {
            config.timeout_ms = std::stoul(argv[++i]);
        }
        else if (arg == "--no-trace")
        {
            config.enable_instruction_trace = false;
        }
        else if (arg == "--no-error-detect")
        {
            config.enable_error_detection = false;
        }
        else if (arg == "--verbose" || arg == "-v")
        {
            config.verbose = true;
        }
        else
        {
            std::cerr << "Error: Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (config.chip_name.empty())
    {
        std::cerr << "Error: --chip is required" << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    if (config.elf_file.empty())
    {
        std::cerr << "Error: --elf is required" << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    // Run simulator
    try
    {
        AKASimulator simulator(config);
        auto result = simulator.run();

        if (!result)
        {
            std::cerr << "\nSimulation failed: " << result.errorMessage() << std::endl;
            return 1;
        }

        SimulationStatus status = result.value();

        if (status == SimulationStatus::Success)
        {
            std::cout << "\n✓ Simulation completed successfully" << std::endl;
            return 0;
        }
        else if (status == SimulationStatus::Error)
        {
            std::cerr << "\n✗ Simulation completed with errors" << std::endl;
            return 1;
        }
        else
        {
            std::cout << "\n⚠ Simulation ended with status: "
                      << static_cast<int>(status) << std::endl;
            return 2;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "\nFatal error: " << e.what() << std::endl;
        return 1;
    }
}