#pragma once

#include "simulator/Types.hpp"
#include <string>
#include <memory>
#include <sstream>

namespace Simulator
{

    /**
     * @brief Source location info for logging
     */
    struct LogLocation
    {
        const char *file;
        int line;
        const char *function;

        LogLocation(const char *f, int l, const char *func)
            : file(f), line(l), function(func) {}

        std::string toString() const
        {
            std::string filename = file;
            // Extract just filename from full path
            size_t pos = filename.find_last_of("/\\");
            if (pos != std::string::npos)
            {
                filename = filename.substr(pos + 1);
            }

            std::ostringstream oss;
            oss << filename << ":" << line << " [" << function << "]";
            return oss.str();
        }
    };

    /**
     * @brief Abstract logger interface
     */
    class ILogger
    {
    public:
        virtual ~ILogger() = default;

        enum class Level
        {
            Trace,
            Debug,
            Info,
            Warning,
            Error,
            Fatal
        };

        /**
         * @brief Log a message with location info
         * @param level Log level
         * @param message Message to log
         * @param location Source location (file, line, function)
         */
        virtual void log(Level level, const std::string &message,
                         const LogLocation &location) = 0;

        // Helper to convert level to string
        static const char *levelToString(Level level)
        {
            switch (level)
            {
            case Level::Trace:
                return "TRACE";
            case Level::Debug:
                return "DEBUG";
            case Level::Info:
                return "INFO ";
            case Level::Warning:
                return "WARN ";
            case Level::Error:
                return "ERROR";
            case Level::Fatal:
                return "FATAL";
            default:
                return "?????";
            }
        }
    };

    // Shared pointer type for convenience
    using LoggerPtr = std::shared_ptr<ILogger>;

} // namespace Simulator

// ============================================================================
// LOGGING MACROS - USE THESE INSTEAD OF CALLING log() DIRECTLY
// ============================================================================

#define LOG_TRACE(logger, msg)                           \
    (logger)->log(Simulator::ILogger::Level::Trace, msg, \
                  Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_DEBUG(logger, msg)                           \
    (logger)->log(Simulator::ILogger::Level::Debug, msg, \
                  Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_INFO(logger, msg)                           \
    (logger)->log(Simulator::ILogger::Level::Info, msg, \
                  Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_WARNING(logger, msg)                           \
    (logger)->log(Simulator::ILogger::Level::Warning, msg, \
                  Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_ERROR(logger, msg)                           \
    (logger)->log(Simulator::ILogger::Level::Error, msg, \
                  Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_FATAL(logger, msg)                           \
    (logger)->log(Simulator::ILogger::Level::Fatal, msg, \
                  Simulator::LogLocation(__FILE__, __LINE__, __func__))

// Formatted logging with std::ostringstream
#define LOG_DEBUG_F(logger)                                        \
    Simulator::LogStream(logger, Simulator::ILogger::Level::Debug, \
                         Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_INFO_F(logger)                                        \
    Simulator::LogStream(logger, Simulator::ILogger::Level::Info, \
                         Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_ERROR_F(logger)                                        \
    Simulator::LogStream(logger, Simulator::ILogger::Level::Error, \
                         Simulator::LogLocation(__FILE__, __LINE__, __func__))

#define LOG_WARNING_F(logger)                           \
    Simulator::LogStream(logger, Simulator::ILogger::Level::Warning, \
                         Simulator::LogLocation(__FILE__, __LINE__, __func__))

// Helper class for formatted logging
namespace Simulator
{
    class LogStream
    {
    public:
        LogStream(LoggerPtr logger, ILogger::Level level, const LogLocation &loc)
            : logger_(logger), level_(level), location_(loc) {}

        ~LogStream()
        {
            logger_->log(level_, stream_.str(), location_);
        }

        template <typename T>
        LogStream &operator<<(const T &value)
        {
            stream_ << value;
            return *this;
        }

    private:
        LoggerPtr logger_;
        ILogger::Level level_;
        LogLocation location_;
        std::ostringstream stream_;
    };
}