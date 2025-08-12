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
#include <regex>
#include <chrono>
#include <ctime>

// For JSON parsing (using a simple JSON parser)
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

struct ComparisonEntry
{
    std::string paramName;
    std::string paramType;
    std::string expectedValue;
    std::string actualValue;
    bool matches;
    int level = 0;        // For nested structure display
    std::string fullPath; // For nested parameters like data[0].a
};

struct FileInfo
{
    std::string filepath;
    std::set<int> coveredLines;
    int errorLine = -1;
    int totalLines = 0;
    std::vector<std::string> sourceLines;
};

struct ExecutionResult
{
    bool success;
    std::string message;
    std::string errorLocation;
    std::string errorFilepath;
    int errorLineNumber = -1;
};

struct TestCaseInfo
{
    std::string testCaseName;
    std::string functionName;
    std::string functionSignature;
    std::string sourceFile;
};

class EnhancedTestReportGenerator
{
private:
    std::map<std::string, FileInfo> fileInfos;
    ExecutionResult execResult;
    std::string outputDir;
    TestCaseInfo testCaseInfo;
    std::vector<ComparisonEntry> comparisonResults;

    // Parse test_case.json to extract test case info
    bool parseTestCaseJson(const std::string &jsonPath)
    {
        std::ifstream file(jsonPath);
        if (!file.is_open())
        {
            std::cerr << "Error: Cannot open test case JSON file: " << jsonPath << std::endl;
            return false;
        }

        json j;
        try
        {
            file >> j;

            // Extract test case name
            testCaseInfo.testCaseName = j["name"];

            // Extract function info from rootDataNode
            std::string functionNode = j["rootDataNode"]["functionNode"];
            // Format: "./input_source/main.c/uut(int,int,char*,MyStruct*,int*,size_t)"

            size_t lastSlash = functionNode.find_last_of('/');
            if (lastSlash != std::string::npos)
            {
                std::string fileAndFunc = functionNode.substr(lastSlash + 1);
                size_t parenPos = fileAndFunc.find('(');
                if (parenPos != std::string::npos)
                {
                    testCaseInfo.functionName = fileAndFunc.substr(0, parenPos);
                    testCaseInfo.functionSignature = fileAndFunc;
                }

                // Extract source file
                std::string filePart = functionNode.substr(0, lastSlash);
                size_t secondLastSlash = filePart.find_last_of('/');
                if (secondLastSlash != std::string::npos)
                {
                    testCaseInfo.sourceFile = filePart.substr(secondLastSlash + 1);
                }
                std::cout << "[PARSE] UUT found: " << testCaseInfo.functionName << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error parsing test case JSON: " << e.what() << std::endl;
            return false;
        }

        file.close();
        return true;
    }

    // Parse actuals.log and build comparison table
    bool parseActualsLog(const std::string &actualsPath, const std::string &jsonPath)
    {
        std::ifstream actualsFile(actualsPath);
        if (!actualsFile.is_open())
        {
            std::cerr << "Error: Cannot open actuals log file: " << actualsPath << std::endl;
            return false;
        }

        // Load JSON for mapping
        std::ifstream jsonFile(jsonPath);
        json testCaseJson;
        jsonFile >> testCaseJson;
        jsonFile.close();

        std::string line;
        while (std::getline(actualsFile, line))
        {
            if (line.find("actual:") == 0)
            {
                // Parse actual/expected line
                std::regex actualExpectedRegex(R"(actual:\s*([^,]+),\s*expected:\s*(.+))");
                std::smatch match;
                if (std::regex_search(line, match, actualExpectedRegex))
                {
                    std::string actualVal = match[1].str();
                    std::string expectedVal = match[2].str();

                    // Read next line for code location
                    std::string codeLine;
                    if (std::getline(actualsFile, codeLine))
                    {
                        if (codeLine.find("\t|-> Code:") == 0)
                        {
                            // Extract the code line
                            size_t codeStart = codeLine.find("(");
                            size_t codeEnd = codeLine.find(")", codeStart);
                            if (codeStart != std::string::npos && codeEnd != std::string::npos)
                            {
                                // Parse the actual source code to extract variable names
                                std::string codeLocation = codeLine.substr(11, codeStart - 12);
                                std::cout << "[PARSE] Code location: " << codeLocation << std::endl;

                                // Read the actual source file and line to get variable info
                                std::string varInfo = extractVariableFromSourceCode(codeLocation, actualVal, expectedVal, testCaseJson);
                                if (!varInfo.empty())
                                {
                                    ComparisonEntry entry = parseVariableInfo(varInfo, actualVal, expectedVal, testCaseJson);
                                    if (!entry.paramName.empty())
                                    {
                                        comparisonResults.push_back(entry);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        actualsFile.close();
        return true;
    }

    // Extract variable information from source code line
    std::string extractVariableFromSourceCode(const std::string &location, const std::string &actual, const std::string &expected, const json &testCaseJson)
    {
        // Parse location: /path/file.c:line
        size_t colonPos = location.find_last_of(':');
        if (colonPos == std::string::npos)
            return "";

        std::string filepath = location.substr(0, colonPos);
        int lineNum = std::stoi(location.substr(colonPos + 1));

        // Read the source file and get the specific line
        std::ifstream file(filepath);
        if (!file.is_open())
            return "";

        std::string line;
        int currentLine = 1;
        while (std::getline(file, line) && currentLine <= lineNum)
        {
            if (currentLine == lineNum)
            {
                // Look for aka_sim_writer_u32(var, EXPECTED_var) pattern
                std::regex writerRegex(R"(aka_sim_writer_u32\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\))");
                std::smatch match;
                if (std::regex_search(line, match, writerRegex))
                {
                    std::string realVar = match[1].str();
                    std::string virtualVar = match[2].str();

                    // Trim whitespace
                    realVar.erase(0, realVar.find_first_not_of(" \t"));
                    realVar.erase(realVar.find_last_not_of(" \t") + 1);
                    virtualVar.erase(0, virtualVar.find_first_not_of(" \t"));
                    virtualVar.erase(virtualVar.find_last_not_of(" \t") + 1);
                    std::cout << "[PARSE] Found variable: " << realVar << ", virtual: " << virtualVar << std::endl;
                    return realVar + "|" + virtualVar;
                }
                break;
            }
            currentLine++;
        }
        file.close();
        return "";
    }

    // Parse variable info and create comparison entry
    ComparisonEntry parseVariableInfo(const std::string &varInfo, const std::string &actual, const std::string &expected, const json &testCaseJson)
    {
        ComparisonEntry entry;

        size_t pipePos = varInfo.find('|');
        if (pipePos == std::string::npos)
            return entry;

        std::string realVar = varInfo.substr(0, pipePos);
        std::string virtualVar = varInfo.substr(pipePos + 1);
        std::cout << "[PARSE] Processing variable: " << realVar << ", virtual: " << virtualVar << std::endl;
        // Find the corresponding variable in JSON
        auto varNode = findVariableInJson(testCaseJson, realVar, virtualVar);
        if (varNode.is_null())
        {
            std::cerr << "[Warning] Variable not found in JSON: " << realVar << " (" << virtualVar << ")" << std::endl;
            return entry; // Skip if variable not found
        }

        entry.paramName = realVar;
        entry.paramType = varNode.value("dataType", "unknown");
        entry.actualValue = actual;
        entry.expectedValue = expected;
        entry.matches = (actual == expected);
        entry.fullPath = realVar;

        return entry;
    }

    // Find variable in JSON structure
    json findVariableInJson(const json &root, const std::string &realName, const std::string &virtualName)
    {
        // Recursively search through the JSON structure
        return searchJsonNode(root, realName, virtualName);
    }

    json searchJsonNode(const json &node, const std::string &realName, const std::string &virtualName)
    {
        // Nếu node là object
        if (node.is_object())
        {
            // Kiểm tra xem node có chứa cả "name" và "virtual_name" với giá trị khớp
            if (node.contains("name") && node.contains("virtual_name") &&
                node["name"].is_string() && node["virtual_name"].is_string() &&
                (node["name"] == realName || node["virtual_name"] == realName))
            {
                return node; // Trả về node nếu khớp
            }
            // Duyệt qua tất cả các key trong object
            for (const auto &item : node.items())
            {
                json result = searchJsonNode(item.value(), realName, virtualName);
                if (!result.is_null())
                {
                    return result; // Trả về node tìm thấy
                }
            }
        }
        // Nếu node là array
        else if (node.is_array())
        {
            // Duyệt qua từng phần tử trong array
            for (const auto &item : node)
            {
                json result = searchJsonNode(item, realName, virtualName);
                if (!result.is_null())
                {
                    return result; // Trả về node tìm thấy
                }
            }
        }
        // Trả về null nếu không tìm thấy
        return json(nullptr);
    }

    // Preprocess log to remove consecutive duplicates
    std::vector<std::string> preprocessLog(const std::vector<std::string> &lines)
    {
        std::vector<std::string> result;
        std::string lastLine = "";

        for (const auto &line : lines)
        {
            if (line != lastLine)
            {
                result.push_back(line);
                lastLine = line;
            }
        }
        return result;
    }

    // Parse code_line.log file
    bool parseCodeLineLog(const std::string &logPath)
    {
        std::ifstream file(logPath);
        if (!file.is_open())
        {
            std::cerr << "Error: Cannot open code line log file: " << logPath << std::endl;
            return false;
        }

        std::vector<std::string> lines;
        std::string line;
        while (std::getline(file, line))
        {
            if (!line.empty())
            {
                lines.push_back(line);
            }
        }
        file.close();

        if (lines.empty())
        {
            std::cerr << "Error: Code line log file is empty" << std::endl;
            return false;
        }

        // Preprocess to remove consecutive duplicates
        lines = preprocessLog(lines);

        // Parse last line for execution result
        std::string lastLine = lines.back();
        if (lastLine.find("# ERROR") == 0)
        {
            execResult.success = false;
            execResult.message = lastLine.substr(8); // Remove "# ERROR"

            // Find error location and mark previous line as error line
            if (lines.size() > 1)
            {
                std::string prevLine = lines[lines.size() - 2];
                parseCodeLine(prevLine, true); // Mark as error line
            }
        }
        else if (lastLine.find("# SUCCESS") == 0)
        {
            execResult.success = true;
            execResult.message = lastLine.substr(10); // Remove "# SUCCESS"
        }

        // Parse covered lines (all lines except the last)
        for (size_t i = 0; i < lines.size() - 1; i++)
        {
            parseCodeLine(lines[i], false);
        }

        return true;
    }

    // Parse individual code line with format: file:line (function)
    void parseCodeLine(const std::string &line, bool isErrorLine)
    {
        // Skip test_driver files
        if (line.find("test_driver/test_driver") != std::string::npos)
        {
            return;
        }

        size_t parenPos = line.find(" (");
        if (parenPos == std::string::npos)
            return;

        std::string fileAndLine = line.substr(0, parenPos);
        size_t colonPos = fileAndLine.rfind(':');
        if (colonPos == std::string::npos)
            return;

        std::string filepath = fileAndLine.substr(0, colonPos);
        int lineNum = std::stoi(fileAndLine.substr(colonPos + 1));

        fileInfos[filepath].coveredLines.insert(lineNum);
        fileInfos[filepath].filepath = filepath;

        if (isErrorLine)
        {
            fileInfos[filepath].errorLine = lineNum;
            execResult.errorFilepath = filepath;
            execResult.errorLineNumber = lineNum;
        }
    }

    // Load source code for each file
    bool loadSourceFiles()
    {
        for (auto &[filepath, fileInfo] : fileInfos)
        {
            std::ifstream file(filepath);
            if (!file.is_open())
            {
                std::cerr << "Warning: Cannot open source file: " << filepath << std::endl;
                continue;
            }

            std::string line;
            while (std::getline(file, line))
            {
                fileInfo.sourceLines.push_back(line);
            }
            fileInfo.totalLines = fileInfo.sourceLines.size();
            file.close();
        }
        return true;
    }

    // Calculate coverage percentage
    double getCoveragePercentage(const FileInfo &fileInfo)
    {
        if (fileInfo.totalLines == 0)
            return 0.0;
        return (double)fileInfo.coveredLines.size() / fileInfo.totalLines * 100.0;
    }

    // Generate CSS styles
    std::string generateCSS()
    {
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

.section {
    background-color: white;
    padding: 15px;
    margin-bottom: 20px;
    border-radius: 5px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.section h2 {
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
    margin-bottom: 15px;
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
    text-decoration: none;
}

.filename:hover {
    color: #3498db;
}

.coverage-bar {
    width: 200px;
    height: 20px;
    background-color: #e0e0e0;
    border-radius: 10px;
    overflow: hidden;
    margin: 0 10px;
    order: 3;
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

.comparison-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}

.comparison-table th,
.comparison-table td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
}

.comparison-table th {
    background-color: #f8f9fa;
}

.comparison-table td.match {
    background-color: #d4edda;
}

.comparison-table td.mismatch {
    background-color: #f8d7da;
}

.comparison-table .nested-param {
    padding-left: 20px;
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

.info-table {
    width: 100%;
    border-collapse: collapse;
}

.info-table th,
.info-table td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
}

.info-table th {
    background-color: #f8f9fa;
    font-weight: bold;
}
)";
    }

    // Generate index.html
    void generateIndexHTML()
    {
        std::ofstream file(outputDir + "/index.html");

        // Calculate overall statistics
        int totalFiles = fileInfos.size();
        int totalCoveredLines = 0;
        int totalLines = 0;

        for (const auto &[filepath, fileInfo] : fileInfos)
        {
            totalCoveredLines += fileInfo.coveredLines.size();
            totalLines += fileInfo.totalLines;
        }

        double overallCoverage = totalLines > 0 ? (double)totalCoveredLines / totalLines * 100.0 : 0.0;

        file << "<!DOCTYPE html>\n<html>\n<head>\n";
        file << "<title>Test Report</title>\n";
        file << "<style>" << generateCSS() << "</style>\n";
        file << "</head>\n<body>\n";

        // Header
        file << "<div class=\"header\">\n";
        file << "<h1>Test Report</h1>\n";
        file << "<p>Generated on " << getCurrentDateTime() << "</p>\n";
        file << "</div>\n";

        // Table of Contents
        file << "<div class=\"section\">\n";
        file << "<h2>Table of Content</h2>\n";
        file << "<ol>\n";
        file << "<li><a href=\"#general-info\" class=\"nav-link\">General information</a></li>\n";
        file << "<li><a href=\"#coverage-summary\" class=\"nav-link\">Coverage summary</a></li>\n";
        file << "<li><a href=\"#test-result\" class=\"nav-link\">Test simulation result</a></li>\n";
        file << "</ol>\n";
        file << "</div>\n";

        // 1. General Information
        file << "<div id=\"general-info\" class=\"section\">\n";
        file << "<h2>General Information</h2>\n";

        file << "<h3>Test report for:</h3>\n";
        file << "<table class=\"info-table\">\n";
        file << "<tr><th>Unit</th><th>Subprogram(s)</th><th>Test case</th></tr>\n";
        file << "<tr><td>" << testCaseInfo.sourceFile << "</td>";
        file << "<td>" << testCaseInfo.functionSignature << "</td>";
        file << "<td>" << testCaseInfo.testCaseName << "</td></tr>\n";
        file << "</table>\n";

        file << "<h3>Simulation status:</h3>\n";
        if (execResult.success)
        {
            file << "<p class=\"status-success\">✅ SUCCESS</p>\n";
            file << "<p><strong>Message:</strong> " << execResult.message << "</p>\n";
        }
        else
        {
            file << "<p class=\"status-error\">❌ ERROR</p>\n";
            file << "<p><strong>Message:</strong> " << execResult.message << "</p>\n";

            // Add link to error location if available
            if (execResult.errorLineNumber > 0 && !execResult.errorFilepath.empty())
            {
                std::string errorFilename = fs::path(execResult.errorFilepath).filename().string();
                std::string errorHtmlFilename = sanitizeFilename(errorFilename) + ".html";
                file << "<p><strong>Error Location:</strong> <a href=\"" << errorHtmlFilename
                     << "#line" << execResult.errorLineNumber << "\" class=\"nav-link\">"
                     << errorFilename << ":" << execResult.errorLineNumber << "</a></p>\n";
            }
        }
        file << "</div>\n";

        // 2. Coverage Summary
        file << "<div id=\"coverage-summary\" class=\"section\">\n";
        file << "<h2>Coverage Summary</h2>\n";
        file << "<p><strong>Files:</strong> " << totalFiles << "</p>\n";
        file << "<p><strong>Total Lines:</strong> " << totalLines << "</p>\n";
        file << "<p><strong>Covered Lines:</strong> " << totalCoveredLines << "</p>\n";
        file << "<p><strong>Coverage:</strong> " << std::fixed << std::setprecision(1) << overallCoverage << "%</p>\n";

        // File list
        file << "<h3>Files</h3>\n";
        for (const auto &[filepath, fileInfo] : fileInfos)
        {
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
            // file << "<p>" << filename << " | " << std::fixed << std::setprecision(1) << coverage << "%</p>\n";
        }
        file << "</div>\n";

        // 3. Test Simulation Result
        file << "<div id=\"test-result\" class=\"section\">\n";
        file << "<h2>Test Simulation Result</h2>\n";

        file << "<h3>" << testCaseInfo.testCaseName << " Result</h3>\n";
        file << "<table class=\"info-table\">\n";
        file << "<tr><th>Result</th><td>" << (execResult.success ? "Success" : "Failed") << "</td></tr>\n";
        file << "</table>\n";

        // Coverage of subprogram
        file << "<h3>Coverage of subprogram</h3>\n";

        // Find the main source file for the unit under test
        std::string mainSourcePath = findMainSourceFile();
        if (!mainSourcePath.empty() && fileInfos.count(mainSourcePath))
        {
            std::string filename = fs::path(mainSourcePath).filename().string();
            std::string htmlFilename = sanitizeFilename(filename) + ".html";
            file << "<p><a href=\"" << htmlFilename << "\" class=\"nav-link\">View " << filename << " coverage</a></p>\n";

            // Generate inline source code display
            generateInlineSourceCode(file, mainSourcePath);
        }

        // Comparison
        file << "<h3>Comparison</h3>\n";
        if (!comparisonResults.empty())
        {
            generateComparisonTable(file);
        }
        else
        {
            file << "<p>No comparison data available.</p>\n";
        }

        file << "</div>\n";

        file << "</body>\n</html>\n";
        file.close();
    }

    // Find the main source file containing the unit under test
    std::string findMainSourceFile()
    {
        for (const auto &[filepath, fileInfo] : fileInfos)
        {
            std::string filename = fs::path(filepath).filename().string();
            if (filename == testCaseInfo.sourceFile)
            {
                return filepath;
            }
        }
        return "";
    }

    // Generate inline source code display
    void generateInlineSourceCode(std::ofstream &file, const std::string &filepath)
    {
        const FileInfo &fileInfo = fileInfos[filepath];

        file << "<div class=\"source-container\">\n";

        for (int i = 0; i < fileInfo.totalLines && i < 100; i++)
        { // Limit to first 100 lines for inline display
            int lineNum = i + 1;
            bool isCovered = fileInfo.coveredLines.count(lineNum) > 0;
            bool isErrorLine = (fileInfo.errorLine == lineNum);

            file << "<div class=\"source-line";
            if (isErrorLine)
            {
                file << " error-line";
            }
            else if (isCovered)
            {
                file << " covered";
            }
            file << "\" id=\"line" << lineNum << "\">\n";

            file << "<div class=\"line-number\">" << lineNum << "</div>\n";
            file << "<div class=\"line-content\">" << htmlEscape(fileInfo.sourceLines[i]) << "</div>\n";
            file << "</div>\n";
        }

        if (fileInfo.totalLines > 100)
        {
            file << "<div style=\"padding: 10px; text-align: center; color: #666;\">\n";
            file << "... (" << (fileInfo.totalLines - 100) << " more lines)\n";
            file << "</div>\n";
        }

        file << "</div>\n";
    }

    // Generate comparison table
    void generateComparisonTable(std::ofstream &file)
    {
        file << "<h4>\tSubprogram: " << testCaseInfo.functionSignature << "</h4>\n";

        file << "<table class=\"comparison-table\">\n";
        file << "<tr><th>Parameter</th><th>Type</th><th>Expected Value</th><th>Actual Value</th></tr>\n";

        int passCount = 0;
        int totalCount = comparisonResults.size();

        for (const auto &entry : comparisonResults)
        {
            std::string cellClass = entry.matches ? "match" : "mismatch";
            if (entry.matches)
                passCount++;

            file << "<tr>\n";
            file << "<td>" << entry.paramName << "</td>\n";
            file << "<td>" << entry.paramType << "</td>\n";
            file << "<td class=\"" << cellClass << "\">" << entry.expectedValue << "</td>\n";
            file << "<td class=\"" << cellClass << "\">" << entry.actualValue << "</td>\n";
            file << "</tr>\n";
        }

        double passPercentage = totalCount > 0 ? (double)passCount / totalCount * 100.0 : 0.0;
        file << "<tr class=\"summary-row\">\n";
        file << "<td colspan=\"2\"><strong>Expected Results matched " << std::fixed << std::setprecision(1) << passPercentage
             << "%</strong></td>\n";
        file << "<td colspan=\"2\"><strong>(" << passCount << "/" << totalCount << ") PASS" << "</strong></td>\n";
        file << "</tr>\n";

        file << "</table>\n";
    }

    // Generate HTML for individual file
    void generateFileHTML(const std::string &filepath, const FileInfo &fileInfo)
    {
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

        // Header - reuse the general information section
        file << "<div class=\"header\">\n";
        file << "<h1>Test Report</h1>\n";
        file << "<p>Generated on " << getCurrentDateTime() << "</p>\n";
        file << "</div>\n";

        // General Information (fixed header)
        file << "<div class=\"section\">\n";
        file << "<h2>General Information</h2>\n";

        file << "<h3>1. Test report for:</h3>\n";
        file << "<table class=\"info-table\">\n";
        file << "<tr><th>Unit</th><th>Subprogram(s)</th><th>Test case</th></tr>\n";
        file << "<tr><td>" << testCaseInfo.sourceFile << "</td>";
        file << "<td>" << testCaseInfo.functionSignature << "</td>";
        file << "<td>" << testCaseInfo.testCaseName << "</td></tr>\n";
        file << "</table>\n";

        file << "<h3>2. Simulation status:</h3>\n";
        if (execResult.success)
        {
            file << "<p class=\"status-success\">SUCCESS</p>\n";
            file << "<p><strong>Message:</strong> " << execResult.message << "</p>\n";
        }
        else
        {
            file << "<p class=\"status-error\">ERROR</p>\n";
            file << "<p><strong>Message:</strong> " << execResult.message << "</p>\n";
        }
        file << "</div>\n";

        // File specific coverage information
        file << "<div class=\"section\">\n";
        file << "<h2>Coverage: " << filename << "</h2>\n";
        file << "<p><strong>File:</strong> " << filepath << "</p>\n";
        file << "<p><strong>Coverage:</strong> " << std::fixed << std::setprecision(1) << coverage << "% ";
        file << "(" << fileInfo.coveredLines.size() << "/" << fileInfo.totalLines << " lines)</p>\n";
        file << "</div>\n";

        // Source code
        file << "<div class=\"source-container\">\n";

        for (int i = 0; i < fileInfo.totalLines; i++)
        {
            int lineNum = i + 1;
            bool isCovered = fileInfo.coveredLines.count(lineNum) > 0;
            bool isErrorLine = (fileInfo.errorLine == lineNum);

            file << "<div class=\"source-line";
            if (isErrorLine)
            {
                file << " error-line";
            }
            else if (isCovered)
            {
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
    std::string getCurrentDateTime()
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    std::string sanitizeFilename(const std::string &filename)
    {
        std::string result = filename;
        std::replace(result.begin(), result.end(), '/', '_');
        std::replace(result.begin(), result.end(), '\\', '_');
        std::replace(result.begin(), result.end(), ':', '_');
        return result;
    }

    std::string htmlEscape(const std::string &text)
    {
        std::string result;
        for (char c : text)
        {
            switch (c)
            {
            case '<':
                result += "&lt;";
                break;
            case '>':
                result += "&gt;";
                break;
            case '&':
                result += "&amp;";
                break;
            case '"':
                result += "&quot;";
                break;
            case '\'':
                result += "&#39;";
                break;
            default:
                result += c;
                break;
            }
        }
        return result;
    }

public:
    EnhancedTestReportGenerator(const std::string &outputDirectory = "test_report")
        : outputDir(outputDirectory)
    {
        execResult.success = false;
    }

    bool generateReport(const std::string &testCaseJsonPath, const std::string &actualsLogPath, const std::string &codeLineLogPath)
    {
        std::cout << "Parsing test case JSON: " << testCaseJsonPath << std::endl;
        if (!parseTestCaseJson(testCaseJsonPath))
        {
            return false;
        }

        std::cout << "Parsing actuals log: " << actualsLogPath << std::endl;
        if (!parseActualsLog(actualsLogPath, testCaseJsonPath))
        {
            std::cerr << "Warning: Could not parse actuals log - continuing without comparison data" << std::endl;
        }

        std::cout << "Parsing code line log: " << codeLineLogPath << std::endl;
        if (!parseCodeLineLog(codeLineLogPath))
        {
            return false;
        }

        std::cout << "Loading source files..." << std::endl;
        if (!loadSourceFiles())
        {
            return false;
        }

        // Create output directory
        if (!fs::exists(outputDir))
        {
            fs::create_directories(outputDir);
        }

        std::cout << "Generating HTML reports..." << std::endl;

        // Generate index page
        generateIndexHTML();

        // Generate individual file pages
        for (const auto &[filepath, fileInfo] : fileInfos)
        {
            generateFileHTML(filepath, fileInfo);
        }

        std::cout << "Test report generated in: " << outputDir << std::endl;
        std::cout << "Open " << outputDir << "/index.html to view the report" << std::endl;

        return true;
    }

    void printStatistics()
    {
        std::cout << "\n=== Test Report Statistics ===" << std::endl;
        std::cout << "Test Case: " << testCaseInfo.testCaseName << std::endl;
        std::cout << "Function: " << testCaseInfo.functionName << std::endl;
        std::cout << "Execution Status: " << (execResult.success ? "SUCCESS" : "ERROR") << std::endl;
        std::cout << "Message: " << execResult.message << std::endl;
        std::cout << "Files processed: " << fileInfos.size() << std::endl;
        std::cout << "Comparison entries: " << comparisonResults.size() << std::endl;

        for (const auto &[filepath, fileInfo] : fileInfos)
        {
            double coverage = getCoveragePercentage(fileInfo);
            std::string filename = fs::path(filepath).filename().string();
            std::cout << "  " << filename << ": " << std::fixed << std::setprecision(1)
                      << coverage << "% (" << fileInfo.coveredLines.size() << "/"
                      << fileInfo.totalLines << " lines)" << std::endl;
        }
    }
};

// Main function
int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        std::cout << "Usage: " << argv[0] << " <test_case.json> <actuals.log> <code_line.log> [output_directory]" << std::endl;
        std::cout << "Example: " << argv[0] << " test_case.json actuals.log code_line.log test_report" << std::endl;
        return 1;
    }

    std::string testCaseJsonPath = argv[1];
    std::string actualsLogPath = argv[2];
    std::string codeLineLogPath = argv[3];
    std::string outputDir = (argc > 4) ? argv[4] : "akas_working_space/output/test_report";

    EnhancedTestReportGenerator generator(outputDir);

    if (generator.generateReport(testCaseJsonPath, actualsLogPath, codeLineLogPath))
    {
        generator.printStatistics();
        return 0;
    }
    else
    {
        std::cerr << "Failed to generate test report" << std::endl;
        return 1;
    }
}