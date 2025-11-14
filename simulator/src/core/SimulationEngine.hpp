#pragma once

#include "simulator/Types.hpp"
#include "architecture/IArchitecture.hpp"
#include "loader/ELFLoader.hpp"
#include "memory/MemoryManager.hpp"
#include "hooks/HookDispatcher.hpp"
#include "tracer/SimulationTracer.hpp"
#include "errors/ErrorDetector.hpp"
#include "stubs/StubManager.hpp"
#include "io/logging/ILogger.hpp"
#include <unicorn/unicorn.h>
#include <memory>
#include <string>

namespace Simulator
{

    /**
     * @brief Configuration for execution
     */
    struct ExecutionConfig
    {
        uint64_t instruction_limit;    // Max instructions (0 = unlimited)
        uint32_t timeout_ms;           // Timeout in milliseconds (0 = no timeout)
        bool enable_instruction_trace; // Trace every instruction
        bool enable_error_detection;   // Detect runtime errors
        bool enable_stubs;             // Use stub functions

        ExecutionConfig()
            : instruction_limit(100000),
              timeout_ms(10000),
              enable_instruction_trace(true),
              enable_error_detection(true),
              enable_stubs(true) {}
    };

    /**
     * @brief Main execution engine - orchestrates everything
     *
     * Responsibilities:
     * - Initialize Unicorn with architecture settings
     * - Setup memory regions
     * - Load ELF binary
     * - Setup hooks and handlers
     * - Run simulation
     * - Collect results
     */
    class SimulationEngine
    {
    public:
        /**
         * @brief Constructor
         * @param architecture Architecture descriptor
         * @param logger Logger
         */
        SimulationEngine(ArchitecturePtr architecture, LoggerPtr logger);

        ~SimulationEngine();

        /**
         * @brief Initialize the engine
         * @param boot_mode Boot mode
         * @return Success or error
         */
        Result<void> initialize(BootMode boot_mode = BootMode::Flash);

        /**
         * @brief Load ELF binary
         * @param elf_path Path to ELF file
         * @return Success or error
         */
        Result<void> loadBinary(const std::string &elf_path);

        /**
         * @brief Load stub definitions (optional)
         * @param stub_file Path to stub file
         * @return Success or error
         */
        Result<void> loadStubs(const std::string &stub_file);

        /**
         * @brief Execute simulation
         * @param config Execution configuration
         * @return Execution status
         */
        Result<ExecutionStatus> execute(const ExecutionConfig &config = ExecutionConfig());

        /**
         * @brief Get binary info
         */
        const BinaryInfo &getBinaryInfo() const { return binary_info_; }

        /**
         * @brief Get simulation tracer (for accessing collected data)
         */
        SimulationTracer *getTracer() { return tracer_.get(); }

        /**
         * @brief Get error detector
         */
        ErrorDetector *getErrorDetector() { return error_detector_.get(); }

        /**
         * @brief Print register state
         */
        void printRegisters() const;

        /**
         * @brief Generate output files
         * @param log_file Execution log path
         * @param trace_file Trace file path (JSON)
         * @param testpath_file Test path file path
         * @return Success or error
         */
        Result<void> generateOutputs(const std::string &log_file,
                                     const std::string &trace_file,
                                     const std::string &testpath_file);

    private:
        ArchitecturePtr architecture_;
        LoggerPtr logger_;

        // Unicorn engine
        uc_engine *uc_;
        bool uc_initialized_;

        // Components
        std::shared_ptr<ELFLoader> elf_loader_;
        std::shared_ptr<MemoryManager> memory_manager_;
        std::shared_ptr<HookDispatcher> hook_dispatcher_;
        std::shared_ptr<SimulationTracer> tracer_;
        std::shared_ptr<ErrorDetector> error_detector_;
        std::shared_ptr<StubManager> stub_manager_;

        // State
        BinaryInfo binary_info_;
        CPUDescriptor cpu_descriptor_;
        BootMode boot_mode_;
        bool binary_loaded_;
        bool stubs_loaded_;

        // Setup methods
        Result<void> initializeUnicorn();
        Result<void> setupCPUState();
        Result<void> setupHooks(const ExecutionConfig &config);
        Result<void> copyBootAlias();
    };

} // namespace Simulator