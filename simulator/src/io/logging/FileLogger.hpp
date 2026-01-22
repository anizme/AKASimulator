#pragma once

#include "ILogger.hpp"
#include <fstream>
#include <mutex>

namespace Simulator {

/**
 * @brief File logger with source location
 */
class FileLogger : public ILogger {
public:
    /**
     * @brief Constructor
     * @param filename Path to log file
     * @param show_location Show source location in log
     * @param min_level Minimum level to log
     */
    explicit FileLogger(const std::string& filename, 
                       bool show_location = true,
                       Level min_level = Level::Debug);
    ~FileLogger();
    
    void log(Level level, const std::string& message, 
             const LogLocation& location) override;
    
    void flush();
    bool isOpen() const { return file_.is_open(); }
    void setShowLocation(bool show) { show_location_ = show; }
    
private:
    std::ofstream file_;
    bool show_location_;
    Level min_level_;
    std::mutex mutex_;
    
    std::string getCurrentTimestamp() const;
};

} // namespace Simulator