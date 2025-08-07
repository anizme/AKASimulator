#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <filesystem>
#include <algorithm>
#include <iomanip>

namespace fs = std::filesystem;

struct FileInfo {
    std::string filepath;
    std::set<int> coveredLines;
    int errorLine = -1;  // Line where error occurred (-1 if no error)
    int totalLines = 0;
    std::vector<std::string> sourceLines;
};

struct ExecutionResult {
    bool success;
    std::string message;
    std::string errorLocation;
    std::string errorFilepath;
    int errorLineNumber = -1;
};

class CoverageReportGenerator {
private:
    std::map<std::string, FileInfo> fileInfos;
    ExecutionResult execResult;
    std::string outputDir;
    
    // Preprocess log to remove consecutive duplicates
    std::vector<std::string> preprocessLog(const std::vector<std::string>& lines) {
        std::vector<std::string> result;
        std::string lastLine = "";
        
        for (const auto& line : lines) {
            if (line != lastLine) {
                result.push_back(line);
                lastLine = line;
            }
        }
        return result;
    }
    
    // Parse log file
    bool parseLogFile(const std::string& logPath) {
        std::ifstream file(logPath);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open log file: " << logPath << std::endl;
            return false;
        }
        
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                lines.push_back(line);
            }
        }
        file.close();
        
        if (lines.empty()) {
            std::cerr << "Error: Log file is empty" << std::endl;
            return false;
        }
        
        // Preprocess to remove consecutive duplicates
        lines = preprocessLog(lines);
        
        // Parse last line for execution result
        std::string lastLine = lines.back();
        if (lastLine.find("# ERROR:") == 0) {
            execResult.success = false;
            execResult.message = lastLine.substr(9); // Remove "# ERROR: "
            
            // Find error location and mark previous line as error line
            if (lines.size() > 1) {
                std::string prevLine = lines[lines.size() - 2];
                size_t colonPos = prevLine.rfind(':');
                if (colonPos != std::string::npos) {
                    std::string filepath = prevLine.substr(0, colonPos);
                    int lineNum = std::stoi(prevLine.substr(colonPos + 1));
                    fileInfos[filepath].errorLine = lineNum;
                    
                    // Store error location for linking
                    execResult.errorFilepath = filepath;
                    execResult.errorLineNumber = lineNum;
                }
            }
        } else if (lastLine.find("# INFO:") == 0) {
            execResult.success = true;
            execResult.message = lastLine.substr(8); // Remove "# INFO: "
        }
        
        // Parse covered lines (all lines except the last)
        for (size_t i = 0; i < lines.size() - 1; i++) {
            const std::string& line = lines[i];
            size_t colonPos = line.rfind(':');
            if (colonPos != std::string::npos) {
                std::string filepath = line.substr(0, colonPos);
                int lineNum = std::stoi(line.substr(colonPos + 1));
                fileInfos[filepath].coveredLines.insert(lineNum);
                fileInfos[filepath].filepath = filepath;
            }
        }
        
        return true;
    }
    
    // Load source code for each file
    bool loadSourceFiles() {
        for (auto& [filepath, fileInfo] : fileInfos) {
            std::ifstream file(filepath);
            if (!file.is_open()) {
                std::cerr << "Warning: Cannot open source file: " << filepath << std::endl;
                continue;
            }
            
            std::string line;
            while (std::getline(file, line)) {
                fileInfo.sourceLines.push_back(line);
            }
            fileInfo.totalLines = fileInfo.sourceLines.size();
            file.close();
        }
        return true;
    }
    
    // Calculate coverage percentage
    double getCoveragePercentage(const FileInfo& fileInfo) {
        if (fileInfo.totalLines == 0) return 0.0;
        return (double)fileInfo.coveredLines.size() / fileInfo.totalLines * 100.0;
    }
    
    // Generate CSS styles
    std::string generateCSS() {
        return R"(
body {
    font-family: Arial, sans-serif;
    margin: 20px;
    background-color: #f5f5f5;
}

.header {
    background-color: #2c3e50;
    color: white;
    padding: 20px;
    margin-bottom: 20px;
    border-radius: 5px;
}

.summary {
    background-color: white;
    padding: 15px;
    margin-bottom: 20px;
    border-radius: 5px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.file-list {
    background-color: white;
    border-radius: 5px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.file-row {
    padding: 10px 15px;
    border-bottom: 1px solid #eee;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.file-row:hover {
    background-color: #f8f9fa;
}

.file-row:last-child {
    border-bottom: none;
}

.filename {
    font-weight: bold;
    color: #2c3e50;
}

.coverage-bar {
    width: 200px;
    height: 20px;
    background-color: #e0e0e0;
    border-radius: 10px;
    overflow: hidden;
    margin: 0 10px;
}

.coverage-fill {
    height: 100%;
    background-color: #27ae60;
    transition: width 0.3s ease;
}

.coverage-text {
    font-weight: bold;
    min-width: 60px;
    text-align: right;
}

.source-container {
    background-color: white;
    border-radius: 5px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    overflow: auto;
    max-height: 70vh;
    border: 1px solid #e0e0e0;
    position: relative;
}

.source-line {
    display: flex;
    font-family: 'Courier New', monospace;
    font-size: 14px;
    line-height: 1.4;
    border-bottom: 1px solid #f0f0f0;
    min-height: 24px;
}

.source-line:last-child {
    border-bottom: none;
}

.line-number {
    background-color: #f8f9fa;
    color: #666;
    padding: 4px 8px;
    min-width: 60px;
    text-align: right;
    border-right: 1px solid #e0e0e0;
    user-select: none;
    position: sticky;
    left: 0;
    z-index: 1;
}

.line-content {
    padding: 4px 8px;
    flex: 1;
    white-space: pre;
    overflow-x: auto;
    word-wrap: break-word;
}

.covered {
    background-color: #e8f5e8;
}

.error-line {
    background-color: #ffebee;
    border-left: 3px solid #f44336;
}

.error-line:target {
    animation: highlight-error 2s ease-in-out;
    box-shadow: 0 0 10px rgba(244, 67, 54, 0.5);
}

@keyframes highlight-error {
    0% { background-color: #ffcdd2; }
    50% { background-color: #ffebee; }
    100% { background-color: #ffebee; }
}

.status-success {
    color: #27ae60;
    font-weight: bold;
}

.status-error {
    color: #e74c3c;
    font-weight: bold;
}

.navigation {
    background-color: white;
    padding: 10px 15px;
    margin-bottom: 20px;
    border-radius: 5px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.nav-link {
    color: #3498db;
    text-decoration: none;
    margin-right: 10px;
}

.nav-link:hover {
    text-decoration: underline;
}
)";
    }
    
    // Generate index.html
    void generateIndexHTML() {
        std::ofstream file(outputDir + "/index.html");
        
        // Calculate overall statistics
        int totalFiles = fileInfos.size();
        int totalCoveredLines = 0;
        int totalLines = 0;
        
        for (const auto& [filepath, fileInfo] : fileInfos) {
            totalCoveredLines += fileInfo.coveredLines.size();
            totalLines += fileInfo.totalLines;
        }
        
        double overallCoverage = totalLines > 0 ? (double)totalCoveredLines / totalLines * 100.0 : 0.0;
        
        file << "<!DOCTYPE html>\n<html>\n<head>\n";
        file << "<title>Coverage Report</title>\n";
        file << "<style>" << generateCSS() << "</style>\n";
        file << "</head>\n<body>\n";
        
        // Header
        file << "<div class=\"header\">\n";
        file << "<h1>Coverage Report</h1>\n";
        file << "<p>Generated on " << getCurrentDateTime() << "</p>\n";
        file << "</div>\n";
        
        // Execution Status
        file << "<div class=\"summary\">\n";
        file << "<h2>Execution Status</h2>\n";
        if (execResult.success) {
            file << "<p class=\"status-success\">✅ SUCCESS</p>\n";
            file << "<p><strong>Message:</strong> " << execResult.message << "</p>\n";
        } else {
            file << "<p class=\"status-error\">❌ ERROR</p>\n";
            file << "<p><strong>Message:</strong> " << execResult.message << "</p>\n";
            
            // Add link to error location if available
            if (execResult.errorLineNumber > 0 && !execResult.errorFilepath.empty()) {
                std::string errorFilename = fs::path(execResult.errorFilepath).filename().string();
                std::string errorHtmlFilename = sanitizeFilename(errorFilename) + ".html";
                file << "<p><strong>Error Location:</strong> <a href=\"" << errorHtmlFilename 
                     << "#line" << execResult.errorLineNumber << "\" class=\"nav-link\">"
                     << errorFilename << ":" << execResult.errorLineNumber << "</a></p>\n";
            }
        }
        file << "</div>\n";
        
        // Summary
        file << "<div class=\"summary\">\n";
        file << "<h2>Coverage Summary</h2>\n";
        file << "<p><strong>Files:</strong> " << totalFiles << "</p>\n";
        file << "<p><strong>Total Lines:</strong> " << totalLines << "</p>\n";
        file << "<p><strong>Covered Lines:</strong> " << totalCoveredLines << "</p>\n";
        file << "<p><strong>Coverage:</strong> " << std::fixed << std::setprecision(1) << overallCoverage << "%</p>\n";
        file << "</div>\n";
        
        // File list
        file << "<div class=\"file-list\">\n";
        file << "<h2 style=\"margin: 0; padding: 15px; background-color: #34495e; color: white;\">Files</h2>\n";
        
        for (const auto& [filepath, fileInfo] : fileInfos) {
            double coverage = getCoveragePercentage(fileInfo);
            std::string filename = fs::path(filepath).filename().string();
            std::string htmlFilename = sanitizeFilename(filename) + ".html";
            
            file << "<div class=\"file-row\">\n";
            file << "<a href=\"" << htmlFilename << "\" class=\"filename\">" << filename << "</a>\n";
            file << "<div class=\"coverage-bar\">\n";
            file << "<div class=\"coverage-fill\" style=\"width: " << coverage << "%\"></div>\n";
            file << "</div>\n";
            file << "<span class=\"coverage-text\">" << std::fixed << std::setprecision(1) << coverage << "%</span>\n";
            file << "</div>\n";
        }
        
        file << "</div>\n";
        file << "</body>\n</html>\n";
        file.close();
    }
    
    // Generate HTML for individual file
    void generateFileHTML(const std::string& filepath, const FileInfo& fileInfo) {
        std::string filename = fs::path(filepath).filename().string();
        std::string htmlFilename = sanitizeFilename(filename) + ".html";
        std::ofstream file(outputDir + "/" + htmlFilename);
        
        double coverage = getCoveragePercentage(fileInfo);
        
        file << "<!DOCTYPE html>\n<html>\n<head>\n";
        file << "<title>Coverage: " << filename << "</title>\n";
        file << "<style>" << generateCSS() << "</style>\n";
        file << "</head>\n<body>\n";
        
        // Navigation
        file << "<div class=\"navigation\">\n";
        file << "<a href=\"index.html\" class=\"nav-link\">← Back to Index</a>\n";
        file << "</div>\n";
        
        // Header
        file << "<div class=\"header\">\n";
        file << "<h1>Coverage: " << filename << "</h1>\n";
        file << "<p><strong>File:</strong> " << filepath << "</p>\n";
        file << "<p><strong>Coverage:</strong> " << std::fixed << std::setprecision(1) << coverage << "% ";
        file << "(" << fileInfo.coveredLines.size() << "/" << fileInfo.totalLines << " lines)</p>\n";
        file << "</div>\n";
        
        // Source code
        file << "<div class=\"source-container\">\n";
        
        for (int i = 0; i < fileInfo.totalLines; i++) {
            int lineNum = i + 1;
            bool isCovered = fileInfo.coveredLines.count(lineNum) > 0;
            bool isErrorLine = (fileInfo.errorLine == lineNum);
            
            file << "<div class=\"source-line";
            if (isErrorLine) {
                file << " error-line";
            } else if (isCovered) {
                file << " covered";
            }
            file << "\" id=\"line" << lineNum << "\">\n";
            
            file << "<div class=\"line-number\">" << lineNum << "</div>\n";
            file << "<div class=\"line-content\">" << htmlEscape(fileInfo.sourceLines[i]) << "</div>\n";
            file << "</div>\n";
        }
        
        file << "</div>\n";
        file << "</body>\n</html>\n";
        file.close();
    }
    
    // Helper functions
    std::string getCurrentDateTime() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    std::string sanitizeFilename(const std::string& filename) {
        std::string result = filename;
        std::replace(result.begin(), result.end(), '/', '_');
        std::replace(result.begin(), result.end(), '\\', '_');
        std::replace(result.begin(), result.end(), ':', '_');
        return result;
    }
    
    std::string htmlEscape(const std::string& text) {
        std::string result;
        for (char c : text) {
            switch (c) {
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '&': result += "&amp;"; break;
                case '"': result += "&quot;"; break;
                case '\'': result += "&#39;"; break;
                default: result += c; break;
            }
        }
        return result;
    }
    
public:
    CoverageReportGenerator(const std::string& outputDirectory = "coverage_report") 
        : outputDir(outputDirectory) {
        execResult.success = false;
    }
    
    bool generateReport(const std::string& logPath) {
        std::cout << "Parsing log file: " << logPath << std::endl;
        if (!parseLogFile(logPath)) {
            return false;
        }
        
        std::cout << "Loading source files..." << std::endl;
        if (!loadSourceFiles()) {
            return false;
        }
        
        // Create output directory
        if (!fs::exists(outputDir)) {
            fs::create_directories(outputDir);
        }
        
        std::cout << "Generating HTML reports..." << std::endl;
        
        // Generate index page
        generateIndexHTML();
        
        // Generate individual file pages
        for (const auto& [filepath, fileInfo] : fileInfos) {
            generateFileHTML(filepath, fileInfo);
        }
        
        std::cout << "Coverage report generated in: " << outputDir << std::endl;
        std::cout << "Open " << outputDir << "/index.html to view the report" << std::endl;
        
        return true;
    }
    
    void printStatistics() {
        std::cout << "\n=== Coverage Statistics ===" << std::endl;
        std::cout << "Execution Status: " << (execResult.success ? "SUCCESS" : "ERROR") << std::endl;
        std::cout << "Message: " << execResult.message << std::endl;
        std::cout << "Files processed: " << fileInfos.size() << std::endl;
        
        for (const auto& [filepath, fileInfo] : fileInfos) {
            double coverage = getCoveragePercentage(fileInfo);
            std::string filename = fs::path(filepath).filename().string();
            std::cout << "  " << filename << ": " << std::fixed << std::setprecision(1) 
                     << coverage << "% (" << fileInfo.coveredLines.size() << "/" 
                     << fileInfo.totalLines << " lines)" << std::endl;
        }
    }
};

// Main function for demonstration
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <log_file> [output_directory]" << std::endl;
        std::cout << "Example: " << argv[0] << " test.log coverage_output" << std::endl;
        return 1;
    }
    
    std::string logFile = argv[1];
    std::string outputDir = (argc > 2) ? argv[2] : "coverage_report";
    
    CoverageReportGenerator generator(outputDir);
    
    if (generator.generateReport(logFile)) {
        generator.printStatistics();
        return 0;
    } else {
        std::cerr << "Failed to generate coverage report" << std::endl;
        return 1;
    }
}