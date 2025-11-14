#include "ConsoleLogger.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>

namespace Simulator
{

    ConsoleLogger::ConsoleLogger(bool enable_colors, bool show_location, Level min_level)
        : enable_colors_(enable_colors), show_location_(show_location), min_level_(min_level)
    {
    }

    void ConsoleLogger::log(Level level, const std::string &message,
                            const LogLocation &location)
    {
        // Filter by minimum level
        if (level < min_level_)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        std::ostream &stream = (level >= Level::Error) ? std::cerr : std::cout;

        // Timestamp
        stream << "[" << getCurrentTimestamp() << "] ";

        // Colored level
        if (enable_colors_)
        {
            stream << getLevelColor(level);
        }
        stream << "[" << levelToString(level) << "]";
        if (enable_colors_)
        {
            stream << "\033[0m"; // Reset color
        }

        // Source location
        if (show_location_)
        {
            if (enable_colors_)
            {
                stream << "\033[90m"; // Dark gray
            }
            stream << " [" << location.toString() << "]";
            if (enable_colors_)
            {
                stream << "\033[0m";
            }
        }

        // Message
        stream << " " << message << std::endl;
    }

    const char *ConsoleLogger::getLevelColor(Level level) const
    {
        switch (level)
        {
        case Level::Trace:
            return "\033[90m"; // Dark gray
        case Level::Debug:
            return "\033[36m"; // Cyan
        case Level::Info:
            return "\033[32m"; // Green
        case Level::Warning:
            return "\033[33m"; // Yellow
        case Level::Error:
            return "\033[31m"; // Red
        case Level::Fatal:
            return "\033[35m"; // Magenta
        default:
            return "\033[0m"; // Reset
        }
    }

    std::string ConsoleLogger::getCurrentTimestamp() const
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        std::tm tm = *std::localtime(&time);

        char buffer[32];
        std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm);

        std::string result = Utils::getCurrentTimestamp();

        // Format milliseconds with leading zeros
        char ms_buffer[8];
        snprintf(ms_buffer, sizeof(ms_buffer), ".%03ld", ms.count());
        result += ms_buffer;

        return result;
    }

} // namespace Simulator