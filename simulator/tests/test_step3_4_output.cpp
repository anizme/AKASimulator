#include "core/SimulationEngine.hpp"
#include "architecture/ArchitectureFactory.hpp"
#include "architecture/arm/chips/STM32F103C8T6.hpp"
#include "io/logging/ConsoleLogger.hpp"

using namespace Simulator;

int main(int argc, char **argv)
{
    auto logger = std::make_shared<ConsoleLogger>();

    LOG_INFO(logger, "=== Testing Step 3.5: Output Generation ===");

    if (argc < 2)
    {
        LOG_ERROR(logger, "Usage: test_step3_4 <elf_file> [stub_file]");
        return 1;
    }

    std::string elf_file = argv[1];
    std::string stub_file = (argc >= 3) ? argv[2] : "";

    // Register and create architecture
    auto &factory = ArchitectureFactory::instance();
    factory.registerArchitecture<ARM::STM32F103C8T6>();
    auto arch = factory.create("stm32f103c8t6").value();

    // Create and initialize engine
    SimulationEngine engine(arch, logger);

    auto init_result = engine.initialize(BootMode::Flash);
    if (!init_result)
    {
        LOG_ERROR_F(logger) << init_result.errorMessage();
        return 1;
    }

    auto load_result = engine.loadBinary(elf_file);
    if (!load_result)
    {
        LOG_ERROR_F(logger) << load_result.errorMessage();
        return 1;
    }

    if (!stub_file.empty())
    {
        engine.loadStubs(stub_file);
    }

    // Execute
    ExecutionConfig config;
    config.instruction_limit = 10000;
    config.enable_instruction_trace = true;
    config.enable_error_detection = true;

    auto exec_result = engine.execute(config);
    if (!exec_result)
    {
        LOG_ERROR_F(logger) << exec_result.errorMessage();
        return 1;
    }

    // Generate outputs
    LOG_INFO(logger, "\n[Test] Generate output files");

    auto output_result = engine.generateOutputs(
        "test_output/execution.log",
        "test_output/trace.trc",
        "test_output/testpath.tp");

    if (!output_result)
    {
        LOG_ERROR_F(logger) << output_result.errorMessage();
        return 1;
    }

    LOG_INFO(logger, "\n=== Check output files ===");
    LOG_INFO(logger, "  - test_output/execution.log");
    LOG_INFO(logger, "  - test_output/trace.trc");
    LOG_INFO(logger, "  - test_output/testpath.tp");

    LOG_INFO(logger, "\n=== All tests passed! ===");

    return 0;
}