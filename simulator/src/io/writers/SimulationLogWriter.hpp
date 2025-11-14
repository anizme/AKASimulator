#pragma once

#include "IOutputWriter.hpp"
#include "io/logging/ILogger.hpp"
#include "io/utils/Symbolizer.hpp"
#include "simulator/Types.hpp"
#include <fstream>
#include <vector>

namespace Simulator
{

    /**
     * @brief Writes execution log with instruction traces
     *
     * Format:
     * [0x08000100] MOVS R0, #0x42
     *     # CodePos: main.c:42:10 (main)
     * [0x08000102] ADDS R1, R0, #3
     *     # CodePos: main.c:43:15 (main)
     */
    class SimulationLogWriter : public IOutputWriter
    {
    public:
        /**
         * @brief Constructor
         * @param output_path Output file path
         * @param traces Instruction traces to write
         * @param binary_info Binary information
         * @param logger Logger
         */
        SimulationLogWriter(const std::string &output_path,
                           const std::vector<InstructionTrace> &traces,
                           const BinaryInfo &binary_info,
                           LoggerPtr logger);

        Result<void> write() override;

        std::string getOutputPath() const override { return output_path_; }

    private:
        std::string output_path_;
        const std::vector<InstructionTrace> &traces_;
        BinaryInfo binary_info_;
        LoggerPtr logger_;

        void writeHeader(std::ofstream &file);
        void writeTrace(std::ofstream &file, const InstructionTrace &trace);
    };

} // namespace Simulator