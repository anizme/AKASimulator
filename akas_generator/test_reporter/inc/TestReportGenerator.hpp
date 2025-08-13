#pragma once

#include "ReportData.hpp"
#include "HtmlGenerator.hpp"
#include <string>
#include <vector>
#include <map>

class TestReportGenerator
{
private:
    std::map<std::string, FileInfo> fileInfos;
    ExecutionResult execResult;
    std::string outputDir;
    TestCaseInfo testCaseInfo;
    std::vector<ComparisonEntry> comparisonResults;
    HtmlGenerator htmlGenerator;

    bool loadSourceFiles();
public:
    TestReportGenerator(const std::string &outputDirectory = "test_report");

    bool generateReport(const std::string &testCaseJsonPath, 
                       const std::string &actualsLogPath, 
                       const std::string &codeLineLogPath);

    void printStatistics();
};