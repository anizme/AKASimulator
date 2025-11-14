#pragma once

#include "simulator/Types.hpp"
#include <string>

namespace Simulator
{

    /**
     * @brief Base interface for output writers
     */
    class IOutputWriter
    {
    public:
        virtual ~IOutputWriter() = default;

        /**
         * @brief Write output to file
         * @return Success or error
         */
        virtual Result<void> write() = 0;

        /**
         * @brief Get output file path
         */
        virtual std::string getOutputPath() const = 0;
    };

} // namespace Simulator