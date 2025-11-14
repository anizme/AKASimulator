#include "AKASimulator.hpp"
#include "io/logging/ILogger.hpp"
#include "io/logging/ConsoleLogger.hpp"
#include "io/logging/FileLogger.hpp"
#include "io/logging/CompositeLogger.hpp"
#include "core/ArchitectureMapper.hpp"
#include "architecture/arm/chips/STM32F103C8T6.hpp"
#include "architecture/arm/chips/STM32F407VG.hpp"
#include <iostream>

namespace Simulator
{

    AKASimulator::AKASimulator(const SimulatorConfig &config)
        : config_(config)
    {
    }

    AKASimulator::~AKASimulator()
    {
        // Cleanup handled by smart pointers
    }

    Result<SimulationStatus> AKASimulator::run()
    {
        LOG_INFO(logger_, "========================================");
        LOG_INFO(logger_, "   Embedded Firmware Simulator");
        LOG_INFO(logger_, "========================================");

        // Step 1: Setup logger
        auto logger_result = setupLogger();
        if (!logger_result)
        {
            return Result<SimulationStatus>::Error(logger_result.errorMessage());
        }

        // Step 2: Setup architecture
        auto arch_result = setupArchitecture();
        if (!arch_result)
        {
            LOG_ERROR_F(logger_) << "Architecture setup failed: " << arch_result.errorMessage();
            return Result<SimulationStatus>::Error(arch_result.errorMessage());
        }

        // Step 3: Create execution engine
        LOG_INFO(logger_, "\n=== Creating Execution Engine ===");
        engine_ = std::make_unique<SimulationEngine>(architecture_, logger_);

        // Step 4: Initialize engine
        auto init_result = engine_->initialize(config_.boot_mode);
        if (!init_result)
        {
            LOG_ERROR_F(logger_) << "Initialization failed: " << init_result.errorMessage();
            return Result<SimulationStatus>::Error(init_result.errorMessage());
        }

        // Step 5: Load binary
        LOG_INFO(logger_, "\n=== Loading Binary ===");
        auto load_result = engine_->loadBinary(config_.elf_file);
        if (!load_result)
        {
            LOG_ERROR_F(logger_) << "Binary loading failed: " << load_result.errorMessage();
            return Result<SimulationStatus>::Error(load_result.errorMessage());
        }

        // Step 6: Load stubs (optional)
        if (!config_.stub_file.empty())
        {
            LOG_INFO(logger_, "\n=== Loading Stubs ===");
            auto stub_result = engine_->loadStubs(config_.stub_file);
            if (!stub_result)
            {
                LOG_WARNING_F(logger_) << "Stub loading failed: " << stub_result.errorMessage();
                LOG_WARNING(logger_, "Continuing without stubs...");
            }
        }

        // Step 7: Execute
        LOG_INFO(logger_, "\n=== Starting Simulation ===");

        ExecutionConfig exec_config;
        exec_config.instruction_limit = config_.instruction_limit;
        exec_config.timeout_ms = config_.timeout_ms;
        exec_config.enable_instruction_trace = config_.enable_instruction_trace;
        exec_config.enable_error_detection = config_.enable_error_detection;
        exec_config.enable_stubs = !config_.stub_file.empty();

        auto exec_result = engine_->execute(exec_config);
        if (!exec_result)
        {
            LOG_ERROR_F(logger_) << "Execution failed: " << exec_result.errorMessage();
            return Result<SimulationStatus>::Error(exec_result.errorMessage());
        }

        SimulationStatus status = exec_result.value();

        // Step 8: Generate outputs
        if (status == SimulationStatus::Success || status == SimulationStatus::Error)
        {
            LOG_INFO(logger_, "\n=== Generating Output Files ===");

            auto output_result = engine_->generateOutputs(
                config_.log_file,
                config_.trace_file,
                config_.testpath_file);

            if (!output_result)
            {
                LOG_WARNING_F(logger_) << "Output generation failed: "
                                       << output_result.errorMessage();
            }
        }

        // Step 9: Summary
        LOG_INFO(logger_, "\n========================================");
        LOG_INFO(logger_, "   Simulation Summary");
        LOG_INFO(logger_, "========================================");

        switch (status)
        {
        case SimulationStatus::Success:
            LOG_INFO(logger_, "Status: SUCCESS");
            break;
        case SimulationStatus::Error:
            LOG_ERROR(logger_, "Status: ERROR");
            if (engine_->getErrorDetector() && engine_->getErrorDetector()->hasError())
            {
                LOG_ERROR_F(logger_) << "Error: "
                                     << engine_->getErrorDetector()->getErrorMessage();
            }
            break;
        case SimulationStatus::Timeout:
            LOG_WARNING(logger_, "Status: TIMEOUT");
            break;
        default:
            LOG_WARNING(logger_, "Status: UNKNOWN");
            break;
        }

        if (engine_->getTracer())
        {
            auto *tracer = engine_->getTracer();
            LOG_INFO_F(logger_) << "Instructions executed: " << tracer->getInstructionCount();
            LOG_INFO_F(logger_) << "Assertions collected: " << tracer->getAssertionEvents().size();
            LOG_INFO_F(logger_) << "Markers collected: " << tracer->getMarkers().size();
        }

        LOG_INFO(logger_, "========================================");

        return Result<SimulationStatus>::Success(status);
    }

    Result<void> AKASimulator::setupLogger()
    {
        auto composite = std::make_shared<CompositeLogger>();

        // Console logger
        auto console = std::make_shared<ConsoleLogger>(
            true,            // colors
            config_.verbose, // show location
            config_.verbose ? ILogger::Level::Debug : ILogger::Level::Info);
        composite->addLogger(console);

        // File logger (if log file specified)
        if (!config_.log_file.empty())
        {
            try
            {
                auto file = std::make_shared<FileLogger>(
                    config_.log_file + ".system.log",
                    config_.verbose,
                    ILogger::Level::Debug);
                composite->addLogger(file);
            }
            catch (const std::exception &e)
            {
                // Can't log yet, just continue with console only
                std::cerr << "Warning: Failed to create file logger: " << e.what() << std::endl;
            }
        }

        logger_ = composite;

        return Result<void>::Success();
    }

    Result<void> AKASimulator::setupArchitecture()
    {
        LOG_INFO(logger_, "\n=== Setting up Architecture ===");

        // Create requested architecture
        auto &factory = ArchitectureFactory::instance();
        auto result = factory.create(config_.chip_name);

        if (!result)
        {
            LOG_ERROR_F(logger_) << "Failed to create architecture: " << result.errorMessage();
            LOG_INFO_F(logger_) << "Available chips: " << factory.getAvailableChips();
            return Result<void>::Error(result.errorMessage());
        }

        architecture_ = result.value();

        LOG_INFO_F(logger_) << "  Chip: " << architecture_->getDescription();

        auto cpu = architecture_->getCPUDescriptor();
        LOG_INFO_F(logger_) << "  CPU: " << ArchitectureMapper::getCPUInfo(cpu);

        auto mem = architecture_->getMemoryMap();
        LOG_INFO_F(logger_) << "  Flash: " << (mem.getFlashSize() / 1024) << " KB";
        LOG_INFO_F(logger_) << "  SRAM: " << (mem.getSRAMSize() / 1024) << " KB";

        return Result<void>::Success();
    }

} // namespace Simulator