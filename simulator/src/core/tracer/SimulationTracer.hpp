#pragma once

#include "simulator/Types.hpp"
#include "core/hooks/HookDispatcher.hpp"
#include "io/logging/ILogger.hpp"
#include "io/utils/Symbolizer.hpp"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <vector>
#include <memory>

namespace Simulator
{

    /**
     * @brief Traces execution and collects data
     *
     * Responsibilities:
     * - Trace instruction execution
     * - Disassemble instructions
     * - Map addresses to source code
     * - Track assertions (AKAS_assert_u32/u64)
     * - Track markers (AKA_mark)
     * - Buffer data for output generation
     */
    class SimulationTracer : public IHookHandler
    {
    public:
        /**
         * @brief Constructor
         * @param uc Unicorn engine instance
         * @param binary_info Binary information from ELF
         * @param logger Logger
         */
        SimulationTracer(uc_engine *uc,
                         const BinaryInfo &binary_info,
                         LoggerPtr logger);

        ~SimulationTracer();

        /**
         * @brief Initialize tracer (setup Capstone, Symbolizer)
         * @return Success or error
         */
        Result<void> initialize();

        /**
         * @brief Hook handler - called on every instruction
         */
        void onCodeExecution(const CodeHookEvent &event) override;

        /**
         * @brief Get collected instruction traces
         */
        const std::vector<InstructionTrace> &getInstructionTraces() const
        {
            return instruction_traces_;
        }

        /**
         * @brief Get collected assertion events
         */
        const std::vector<AssertionEvent> &getAssertionEvents() const
        {
            return assertion_events_;
        }

        /**
         * @brief Get collected marker positions (for test path)
         */
        const std::vector<std::string> &getMarkers() const
        {
            return markers_;
        }

        /**
         * @brief Get total instruction count
         */
        size_t getInstructionCount() const { return instruction_count_; }

        /**
         * @brief Enable/disable instruction tracing
         */
        void setEnableInstructionTrace(bool enable)
        {
            enable_instruction_trace_ = enable;
        }

    private:
        uc_engine *uc_;
        BinaryInfo binary_info_;
        LoggerPtr logger_;

        csh capstone_handle_;
        std::unique_ptr<Symbolizer> symbolizer_;

        bool enable_instruction_trace_;
        size_t instruction_count_;

        // Buffered data
        std::vector<InstructionTrace> instruction_traces_;
        std::vector<AssertionEvent> assertion_events_;
        std::vector<std::string> markers_;

        // For detecting main return
        Address main_return_address_;

        // Handle specific hooks
        void handleInstructionTrace(const CodeHookEvent &event);
        void handleAssertU32(Address address);
        void handleAssertU64(Address address);
        void handleMark(Address address);

        // Disassemble instruction
        bool disassembleInstruction(const CodeHookEvent &event, InstructionTrace &trace);

        // Read source line at address
        std::string readSourceLine(const SourceInfo &info);
    };

} // namespace Simulator