#pragma once

#include "IOutputWriter.hpp"
#include "io/logging/ILogger.hpp"
#include <vector>
#include <string>

namespace Simulator
{

    /**
     * @brief Writes test path file
     *
     * Format: One marker per line
     * path_1_entry
     * condition_checked_true
     * loop_iteration_1
     * ...
     */
    class TestPathWriter : public IOutputWriter
    {
    public:
        /**
         * @brief Constructor
         * @param output_path Output file path
         * @param markers Marker strings to write
         * @param logger Logger
         */
        TestPathWriter(const std::string &output_path,
                       const std::vector<std::string> &markers,
                       LoggerPtr logger);

        Result<void> write() override;

        std::string getOutputPath() const override { return output_path_; }

    private:
        std::string output_path_;
        const std::vector<std::string> &markers_;
        LoggerPtr logger_;
    };

} // namespace Simulator