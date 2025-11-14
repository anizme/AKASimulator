#include "TraceFileWriter.hpp"
#include "io/utils/FileUtils.hpp"
#include <fstream>

namespace Simulator
{

    TraceFileWriter::TraceFileWriter(
        const std::string &output_path,
        const std::vector<AssertionEvent> &assertions,
        LoggerPtr logger)
        : output_path_(output_path), assertions_(assertions), logger_(logger)
    {
    }

    Result<void> TraceFileWriter::write()
    {
        LOG_INFO_F(logger_) << "Writing trace file to: " << output_path_;

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

        // Write JSON array
        file << "[\n";

        for (size_t i = 0; i < assertions_.size(); ++i)
        {
            writeAssertion(file, assertions_[i]);

            if (i < assertions_.size() - 1)
            {
                file << ",\n";
            }
            else
            {
                file << "\n";
            }
        }

        file << "]\n";

        file.close();

        LOG_INFO_F(logger_) << "  ✓ Wrote " << assertions_.size() << " assertions";

        return Result<void>::Success();
    }

    void TraceFileWriter::writeAssertion(std::ofstream &file, const AssertionEvent &event)
    {
        file << "  {\n";
        file << "    \"tag\": \"Aka function calls: " << event.fcall_count << "\",\n";
        file << "    \"actualName\": \"" << event.actual_name << "\",\n";
        file << "    \"actualVal\": \"" << event.actual_value << "\",\n";
        file << "    \"expectedName\": \"" << event.expected_name << "\",\n";
        file << "    \"expectedVal\": \"" << event.expected_value << "\"\n";
        file << "  }";
    }

} // namespace Simulator