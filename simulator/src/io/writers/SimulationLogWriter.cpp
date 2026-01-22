#include "SimulationLogWriter.hpp"
#include "io/utils/StringUtils.hpp"
#include "io/utils/FileUtils.hpp"
#include <iomanip>

namespace Simulator
{

    SimulationLogWriter::SimulationLogWriter(
        const std::string &output_path,
        const std::vector<InstructionTrace> &traces,
        const BinaryInfo &binary_info,
        LoggerPtr logger)
        : output_path_(output_path), traces_(traces),
          binary_info_(binary_info), logger_(logger)
    {
    }

    Result<void> SimulationLogWriter::write()
    {
        LOG_INFO_F(logger_) << "Writing execution log to: " << output_path_;

        // Create directory if needed
        std::string dir = Utils::getDirectory(output_path_);
        if (!dir.empty())
        {
            Utils::createDirectory(dir);
        }

        // Open file
        std::ofstream file(output_path_);
        if (!file.is_open())
        {
            return Result<void>::Error("Failed to open file: " + output_path_);
        }

        // Write header
        writeHeader(file);

        // Write traces
        size_t count = 0;
        for (const auto &trace : traces_)
        {
            writeTrace(file, trace);
            count++;

            // Flush periodically
            if (count % 1000 == 0)
            {
                file.flush();
            }
        }

        file.close();

        LOG_INFO_F(logger_) << "  ✓ Wrote " << count << " instruction traces";

        return Result<void>::Success();
    }

    void SimulationLogWriter::writeHeader(std::ofstream &file)
    {
        file << "# ============================================\n";
        file << "# Execution Log\n";
        file << "# ============================================\n";
        file << "# ELF File: " << binary_info_.file_path << "\n";
        file << "# Entry Point: " << Utils::formatHex(binary_info_.entry_point) << "\n";
        file << "# Main Address: " << Utils::formatHex(binary_info_.main_address) << "\n";
        file << "# Generated: " << Utils::getCurrentTimestamp() << "\n";
        file << "# ============================================\n";
        file << "\n";
    }

    void SimulationLogWriter::writeTrace(std::ofstream &file, const InstructionTrace &trace)
    {
        // Format: [ADDRESS] MNEMONIC OPERANDS
        file << "[" << Utils::formatHex(trace.address) << "] "
             << std::left << std::setw(8) << trace.mnemonic;

        if (!trace.operands.empty())
        {
            file << " " << trace.operands;
        }

        file << "\n";

        // Source info
        if (trace.source_info.isValid())
        {
            file << "    # CodePos: " << trace.source_info.toString() << "\n";
        }
        else
        {
            file << "    # CodePos: unknown\n";
        }
    }

} // namespace Simulator