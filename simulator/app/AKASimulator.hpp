#pragma once

#include "core/SimulationEngine.hpp"
#include "architecture/ArchitectureFactory.hpp"
#include "io/logging/ILogger.hpp"
#include "simulator/Types.hpp"
#include <string>
#include <memory>

namespace Simulator
{

    /**
     * @brief Configuration for the simulator
     */
    struct SimulatorConfig
    {
        // Architecture
        std::string chip_name; // "stm32f103c8t6"
        BootMode boot_mode;    // Flash, SRAM, SystemMemory

        // Input files
        std::string elf_file;
        std::string stub_file; // Optional

        // Output files
        std::string log_file;
        std::string trace_file;
        std::string testpath_file;

        // Execution settings
        uint64_t instruction_limit;
        uint32_t timeout_ms;
        bool enable_instruction_trace;
        bool enable_error_detection;

        // Logging
        bool verbose;

        SimulatorConfig()
            : boot_mode(BootMode::Flash),
              instruction_limit(100000),
              timeout_ms(10000),
              enable_instruction_trace(true),
              enable_error_detection(true),
              verbose(false) {}
    };

    /**
     * @brief High-level simulator API
     *
     * This is the main entry point for using the simulator.
     * Wraps all complexity and provides a simple interface.
     */
    class AKASimulator
    {
    public:
        /**
         * @brief Constructor
         * @param config Simulator configuration
         */
        explicit AKASimulator(const SimulatorConfig &config);

        ~AKASimulator();

        /**
         * @brief Run the simulation
         * @return Success or error
         */
        Result<SimulationStatus> run();

        /**
         * @brief Get execution engine (for advanced usage)
         */
        SimulationEngine *getEngine() { return engine_.get(); }

    private:
        SimulatorConfig config_;
        LoggerPtr logger_;
        ArchitecturePtr architecture_;
        std::unique_ptr<SimulationEngine> engine_;

        // Setup steps
        Result<void> setupLogger();
        Result<void> setupArchitecture();
    };

} // namespace Simulator