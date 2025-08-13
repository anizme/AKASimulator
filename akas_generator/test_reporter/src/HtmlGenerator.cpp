#include "HtmlGenerator.hpp"
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sstream>

namespace fs = std::filesystem;

HtmlGenerator::HtmlGenerator(const std::string &outputDir) : outputDir(outputDir) {}

void HtmlGenerator::generateIndexHTML(const std::map<std::string, FileInfo> &fileInfos,
                                     const ExecutionResult &execResult,
                                     const TestCaseInfo &testCaseInfo,
                                     const std::vector<ComparisonEntry> &comparisonResults)
{
    std::ofstream file(outputDir + "/index.html");

    file << "<!DOCTYPE html>\n<html>\n<head>\n";
    file << "<title>Test Report</title>\n";
    file << "<link rel=\"stylesheet\" href=\"styles/styles.css\">\n";
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

    // Generate sections
    generateGeneralInfoSection(file, testCaseInfo, execResult);
    generateCoverageSummary(file, fileInfos);
    generateTestResult(file, testCaseInfo, execResult, comparisonResults, fileInfos);

    file << "</body>\n</html>\n";
    file.close();
}

void HtmlGenerator::generateFileHTML(const std::string &filepath, const FileInfo &fileInfo,
                                    const TestCaseInfo &testCaseInfo,
                                    const ExecutionResult &execResult)
{
    std::string filename = fs::path(filepath).filename().string();
    std::string htmlFilename = sanitizeFilename(filename) + ".html";
    std::ofstream file(outputDir + "/" + htmlFilename);

    double coverage = getCoveragePercentage(fileInfo);

    file << "<!DOCTYPE html>\n<html>\n<head>\n";
    file << "<title>Coverage: " << filename << "</title>\n";
    file << "<link rel=\"stylesheet\" href=\"styles/styles.css\">\n";
    file << "</head>\n<body>\n";

    // Navigation
    file << "<div class=\"navigation\">\n";
    file << "<a href=\"index.html\" class=\"nav-link\">← Back to Index</a>\n";
    file << "</div>\n";

    // Header
    file << "<div class=\"header\">\n";
    file << "<h1>Test Report</h1>\n";
    file << "<p>Generated on " << getCurrentDateTime() << "</p>\n";
    file << "</div>\n";

    // General Information
    generateGeneralInfoSection(file, testCaseInfo, execResult);

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

void HtmlGenerator::generateGeneralInfoSection(std::ofstream &file, const TestCaseInfo &testCaseInfo, 
                                              const ExecutionResult &execResult)
{
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
}

void HtmlGenerator::generateCoverageSummary(std::ofstream &file, const std::map<std::string, FileInfo> &fileInfos)
{
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
    }
    file << "</div>\n";
}

void HtmlGenerator::generateTestResult(std::ofstream &file, const TestCaseInfo &testCaseInfo, 
                                      const ExecutionResult &execResult,
                                      const std::vector<ComparisonEntry> &comparisonResults,
                                      const std::map<std::string, FileInfo> &fileInfos)
{
    file << "<div id=\"test-result\" class=\"section\">\n";
    file << "<h2>Test Simulation Result</h2>\n";

    file << "<h3>" << testCaseInfo.testCaseName << " Result</h3>\n";
    file << "<table class=\"info-table\">\n";
    file << "<tr><th>Result</th><td>" << (execResult.success ? "Success" : "Failed") << "</td></tr>\n";
    file << "</table>\n";

    // Coverage of subprogram
    file << "<h3>Coverage of subprogram</h3>\n";

    // Find the main source file for the unit under test
    std::string mainSourcePath = findMainSourceFile(fileInfos, testCaseInfo);
    if (!mainSourcePath.empty() && fileInfos.count(mainSourcePath))
    {
        std::string filename = fs::path(mainSourcePath).filename().string();
        std::string htmlFilename = sanitizeFilename(filename) + ".html";
        file << "<p><a href=\"" << htmlFilename << "\" class=\"nav-link\">View " << filename << " coverage</a></p>\n";

        // Generate inline source code display
        generateInlineSourceCode(file, mainSourcePath, fileInfos);
    }

    // Comparison
    file << "<h3>Comparison</h3>\n";
    if (!comparisonResults.empty())
    {
        generateComparisonTable(file, testCaseInfo, comparisonResults);
    }
    else
    {
        file << "<p>No comparison data available.</p>\n";
    }

    file << "</div>\n";
}

void HtmlGenerator::generateInlineSourceCode(std::ofstream &file, const std::string &filepath,
                                            const std::map<std::string, FileInfo> &fileInfos)
{
    const FileInfo &fileInfo = fileInfos.at(filepath);

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

void HtmlGenerator::generateComparisonTable(std::ofstream &file, const TestCaseInfo &testCaseInfo,
                                           const std::vector<ComparisonEntry> &comparisonResults)
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

std::string HtmlGenerator::findMainSourceFile(const std::map<std::string, FileInfo> &fileInfos, 
                                             const TestCaseInfo &testCaseInfo)
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

double HtmlGenerator::getCoveragePercentage(const FileInfo &fileInfo)
{
    if (fileInfo.totalLines == 0)
        return 0.0;
    return (double)fileInfo.coveredLines.size() / fileInfo.totalLines * 100.0;
}

std::string HtmlGenerator::getCurrentDateTime()
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string HtmlGenerator::sanitizeFilename(const std::string &filename)
{
    std::string result = filename;
    std::replace(result.begin(), result.end(), '/', '_');
    std::replace(result.begin(), result.end(), '\\', '_');
    std::replace(result.begin(), result.end(), ':', '_');
    return result;
}

std::string HtmlGenerator::htmlEscape(const std::string &text)
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
