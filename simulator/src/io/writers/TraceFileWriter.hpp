#pragma once

#include "IOutputWriter.hpp"
#include "io/logging/ILogger.hpp"
#include "simulator/Types.hpp"
#include <vector>

namespace Simulator
{

    /**
     * @brief Writes trace file in JSON format
     *
     * Format:
     * [
     *   {
     *     "tag": "Aka function calls: 1",
     *     "actualName": "counter",
     *     "actualVal": "42",
     *     "expectedName": "EXPECTED_counter",
     *     "expectedVal": "42"
     *   },
     *   ...
     * ]
     */
    class TraceFileWriter : public IOutputWriter
    {
    public:
        /**
         * @brief Constructor
         * @param output_path Output file path
         * @param assertions Assertion events to write
         * @param logger Logger
         */
        TraceFileWriter(const std::string &output_path,
                        const std::vector<AssertionEvent> &assertions,
                        LoggerPtr logger);

        Result<void> write() override;

        std::string getOutputPath() const override { return output_path_; }

    private:
        std::string output_path_;
        const std::vector<AssertionEvent> &assertions_;
        LoggerPtr logger_;

        void writeAssertion(std::ofstream &file, const AssertionEvent &event);
    };

} // namespace Simulator