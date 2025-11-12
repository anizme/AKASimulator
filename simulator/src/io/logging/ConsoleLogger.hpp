#pragma once

#include "ILogger.hpp"
#include <mutex>

namespace Simulator
{

    /**
     * @brief Console logger with colored output and source location
     */
    class ConsoleLogger : public ILogger
    {
    public:
        /**
         * @brief Constructor
         * @param enable_colors Enable ANSI color codes
         * @param show_location Show source location (file:line [function])
         * @param min_level Minimum level to log
         */
        explicit ConsoleLogger(bool enable_colors = true,
                               bool show_location = true,
                               Level min_level = Level::Debug);

        void log(Level level, const std::string &message,
                 const LogLocation &location) override;

        void setMinLevel(Level level) { min_level_ = level; }
        void setShowLocation(bool show) { show_location_ = show; }

    private:
        bool enable_colors_;
        bool show_location_;
        Level min_level_;
        std::mutex mutex_;

        const char *getLevelColor(Level level) const;
        std::string getCurrentTimestamp() const;
    };

} // namespace Simulator