#include "core/SimulationEngine.hpp"
#include "architecture/ArchitectureFactory.hpp"
#include "architecture/arm/chips/STM32F103C8T6.hpp"
#include "io/logging/ConsoleLogger.hpp"

using namespace Simulator;

int main(int argc, char **argv)
{
    auto logger = std::make_shared<ConsoleLogger>();

    LOG_INFO(logger, "=== Testing Step 3.4: Execution Engine ===");

    // Check arguments
    if (argc < 2)
    {
        LOG_ERROR(logger, "Usage: test_step3_4 <elf_file> [stub_file]");
        return 1;
    }

    std::string elf_file = argv[1];
    std::string stub_file = (argc >= 3) ? argv[2] : "";

    // Register architecture
    auto &factory = ArchitectureFactory::instance();
    factory.registerArchitecture<ARM::STM32F103C8T6>();

    // Create architecture
    auto arch_result = factory.create("stm32f103c8t6");
    if (!arch_result)
    {
        LOG_ERROR_F(logger) << "Failed: " << arch_result.errorMessage();
        return 1;
    }

    auto arch = arch_result.value();

    // Create execution engine
    LOG_INFO(logger, "\n[Test 1] Create SimulationEngine");
    SimulationEngine engine(arch, logger);
    LOG_INFO(logger, "  ✓ Engine created");

    // Initialize
    LOG_INFO(logger, "\n[Test 2] Initialize engine");
    auto init_result = engine.initialize(BootMode::Flash);
    if (!init_result)
    {
        LOG_ERROR_F(logger) << "Failed: " << init_result.errorMessage();
        return 1;
    }
    LOG_INFO(logger, "  ✓ Engine initialized");

    // Load binary
    LOG_INFO(logger, "\n[Test 3] Load ELF binary");
    auto load_result = engine.loadBinary(elf_file);
    if (!load_result)
    {
        LOG_ERROR_F(logger) << "Failed: " << load_result.errorMessage();
        return 1;
    }
    LOG_INFO(logger, "  ✓ Binary loaded");

    // Load stubs (optional)
    if (!stub_file.empty())
    {
        LOG_INFO(logger, "\n[Test 4] Load stubs");
        auto stub_result = engine.loadStubs(stub_file);
        if (!stub_result)
        {
            LOG_WARNING_F(logger) << "Stub loading failed: " << stub_result.errorMessage();
        }
        else
        {
            LOG_INFO(logger, "  ✓ Stubs loaded");
        }
    }

    // Execute
    LOG_INFO(logger, "\n[Test 5] Execute simulation");

    ExecutionConfig config;
    config.instruction_limit = 10000;
    config.enable_instruction_trace = true;
    config.enable_error_detection = true;
    config.enable_stubs = true;

    auto exec_result = engine.execute(config);
    if (!exec_result)
    {
        LOG_ERROR_F(logger) << "Failed: " << exec_result.errorMessage();
        return 1;
    }

    SimulationStatus status = exec_result.value();
    LOG_INFO_F(logger) << "  Execution status: " << static_cast<int>(status);

    // Print final state
    LOG_INFO(logger, "\n[Test 6] Final state");
    engine.printRegisters();

    // Print trace summary
    if (engine.getTracer())
    {
        auto *tracer = engine.getTracer();
        LOG_INFO_F(logger) << "\nTrace Summary:";
        LOG_INFO_F(logger) << "  Instructions executed: " << tracer->getInstructionCount();
        LOG_INFO_F(logger) << "  Assertions: " << tracer->getAssertionEvents().size();
        LOG_INFO_F(logger) << "  Markers: " << tracer->getMarkers().size();
    }

    LOG_INFO(logger, "=== All tests passed! ===");

    return 0;
}