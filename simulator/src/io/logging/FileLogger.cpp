#include "FileLogger.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <filesystem>

namespace Simulator {

FileLogger::FileLogger(const std::string& filename, bool show_location, Level min_level)
    : show_location_(show_location), min_level_(min_level) {
    
    // Create directory if it doesn't exist
    std::filesystem::path filepath(filename);
    auto parent = filepath.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            std::cerr << "Warning: Failed to create log directory: " << ec.message() << std::endl;
        }
    }
    
    file_.open(filename);
    if (!file_.is_open()) {
        throw std::runtime_error("Failed to open log file: " + filename);
    }
}

FileLogger::~FileLogger() {
    if (file_.is_open()) {
        file_.close();
    }
}

void FileLogger::log(Level level, const std::string& message, 
                    const LogLocation& location) {
    if (level < min_level_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!file_.is_open()) {
        return;
    }
    
    file_ << "[" << getCurrentTimestamp() << "] "
          << "[" << levelToString(level) << "] ";
    
    if (show_location_) {
        file_ << "[" << location.toString() << "] ";
    }
    
    file_ << message << std::endl;
}

void FileLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.flush();
    }
}

std::string FileLogger::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::tm tm = *std::localtime(&time);
    
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
    
    return buffer;
}

} // namespace Simulator