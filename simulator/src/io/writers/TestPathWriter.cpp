#include "TestPathWriter.hpp"
#include "io/utils/FileUtils.hpp"
#include <fstream>

namespace Simulator
{

    TestPathWriter::TestPathWriter(
        const std::string &output_path,
        const std::vector<std::string> &markers,
        LoggerPtr logger)
        : output_path_(output_path), markers_(markers), logger_(logger)
    {
    }

    Result<void> TestPathWriter::write()
    {
        LOG_INFO_F(logger_) << "Writing test path file to: " << output_path_;

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

        // Write markers
        for (const auto &marker : markers_)
        {
            file << marker << "\n";
        }

        file.close();

        LOG_INFO_F(logger_) << "  ✓ Wrote " << markers_.size() << " markers";

        return Result<void>::Success();
    }

} // namespace Simulator