#include "TestReportGenerator.hpp"
#include "JsonParser.hpp"
#include "LogParser.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>

namespace fs = std::filesystem;

TestReportGenerator::TestReportGenerator(const std::string &outputDirectory)
    : outputDir(outputDirectory), htmlGenerator(outputDirectory)
{
    execResult.success = false;
}

bool TestReportGenerator::generateReport(const std::string &testCaseJsonPath, 
                                        const std::string &actualsLogPath, 
                                        const std::string &codeLineLogPath)
{
    std::cout << "Parsing test case JSON: " << testCaseJsonPath << std::endl;
    if (!JsonParser::parseTestCaseJson(testCaseJsonPath, testCaseInfo))
    {
        return false;
    }

    std::cout << "Parsing actuals log: " << actualsLogPath << std::endl;
    if (!LogParser::parseActualsLog(actualsLogPath, testCaseJsonPath, comparisonResults))
    {
        std::cerr << "Warning: Could not parse actuals log - continuing without comparison data" << std::endl;
    }

    std::cout << "Parsing code line log: " << codeLineLogPath << std::endl;
    if (!LogParser::parseCodeLineLog(codeLineLogPath, fileInfos, execResult))
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
    htmlGenerator.generateIndexHTML(fileInfos, execResult, testCaseInfo, comparisonResults);

    // Generate individual file pages
    for (const auto &[filepath, fileInfo] : fileInfos)
    {
        htmlGenerator.generateFileHTML(filepath, fileInfo, testCaseInfo, execResult);
    }

    std::cout << "Test report generated in: " << outputDir << std::endl;
    std::cout << "Open " << outputDir << "/index.html to view the report" << std::endl;

    return true;
}

bool TestReportGenerator::loadSourceFiles()
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

void TestReportGenerator::printStatistics()
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
        double coverage = (fileInfo.totalLines == 0) ? 0.0 : 
            (double)fileInfo.coveredLines.size() / fileInfo.totalLines * 100.0;
        std::string filename = fs::path(filepath).filename().string();
        std::cout << "  " << filename << ": " << std::fixed << std::setprecision(1)
                  << coverage << "% (" << fileInfo.coveredLines.size() << "/"
                  << fileInfo.totalLines << " lines)" << std::endl;
    }
}