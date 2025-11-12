#pragma once

#include "ILogger.hpp"
#include <vector>

namespace Simulator
{

    /**
     * @brief Composite logger that forwards to multiple loggers
     */
    class CompositeLogger : public ILogger
    {
    public:
        CompositeLogger() = default;

        void addLogger(LoggerPtr logger)
        {
            loggers_.push_back(logger);
        }

        void log(Level level, const std::string &message,
                 const LogLocation &location) override
        {
            for (auto &logger : loggers_)
            {
                logger->log(level, message, location);
            }
        }

    private:
        std::vector<LoggerPtr> loggers_;
    };

} // namespace Simulator