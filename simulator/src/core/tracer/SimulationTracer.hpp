#pragma once

#include "simulator/Types.hpp"
#include "core/hooks/HookDispatcher.hpp"
#include "architecture/Descriptors.hpp"
#include "io/logging/ILogger.hpp"
#include "io/utils/Symbolizer.hpp"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <vector>
#include <unordered_map>
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
                         LoggerPtr logger,
                         CPUDescriptor cpu_descriptor, 
                         bool trace_from_main, 
                         bool break_loop, 
                         int loop_limit);

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

    private:
        uc_engine *uc_;
        BinaryInfo binary_info_;
        LoggerPtr logger_;
        CPUDescriptor cpu_descriptor_;

        csh capstone_handle_;
        std::unique_ptr<Symbolizer> symbolizer_;

        bool trace_from_main_;
        bool is_in_main_;
        size_t instruction_count_;

        bool break_loop_;
        std::unordered_map<Address, int> loop_counter_;
        std::unordered_map<Address, Address> loop_escape_map_;
        int max_loop_ = 100;
        int max_self_loop_ = 2;

        // Buffered data
        std::vector<InstructionTrace> instruction_traces_;
        std::vector<AssertionEvent> assertion_events_;
        std::vector<std::string> markers_;

        // For detecting main return
        Address main_return_address_;

        // Track previous instruction for parsing caller of AKA_mark, AKAS_assert
        Address previous_instruction_address_;

        // Handle specific hooks
        void handleInstructionTrace(const CodeHookEvent &event);
        void handleAssertU32(Address caller_address);
        void handleAssertU64(Address caller_address);
        void handleMark(Address caller_address);
        void handleLoopBreak(const CodeHookEvent &event);

        // Disassemble instruction
        bool disassembleInstruction(const CodeHookEvent &event, InstructionTrace &trace);

        // Read source line at address
        std::string readSourceLine(const SourceInfo &info);

        bool getBranchTarget(cs_insn *insn, Address *target);
        bool isLoopBranch(cs_insn *insn);
    };

} // namespace Simulator