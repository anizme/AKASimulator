#pragma once

#include "ReportData.hpp"
#include <string>
#include <map>
#include <vector>
#include <fstream>

class HtmlGenerator
{
public:
    HtmlGenerator(const std::string &outputDir);

    void generateIndexHTML(const std::map<std::string, FileInfo> &fileInfos,
                          const ExecutionResult &execResult,
                          const TestCaseInfo &testCaseInfo,
                          const std::vector<ComparisonEntry> &comparisonResults);

    void generateFileHTML(const std::string &filepath, const FileInfo &fileInfo,
                         const TestCaseInfo &testCaseInfo,
                         const ExecutionResult &execResult);

private:
    std::string outputDir;

    void generateGeneralInfoSection(std::ofstream &file, const TestCaseInfo &testCaseInfo, 
                                   const ExecutionResult &execResult);
    void generateCoverageSummary(std::ofstream &file, const std::map<std::string, FileInfo> &fileInfos);
    void generateTestResult(std::ofstream &file, const TestCaseInfo &testCaseInfo, 
                           const ExecutionResult &execResult,
                           const std::vector<ComparisonEntry> &comparisonResults,
                           const std::map<std::string, FileInfo> &fileInfos);
    void generateInlineSourceCode(std::ofstream &file, const std::string &filepath,
                                 const std::map<std::string, FileInfo> &fileInfos);
    void generateComparisonTable(std::ofstream &file, const TestCaseInfo &testCaseInfo,
                                const std::vector<ComparisonEntry> &comparisonResults);

    std::string findMainSourceFile(const std::map<std::string, FileInfo> &fileInfos, 
                                  const TestCaseInfo &testCaseInfo);
    double getCoveragePercentage(const FileInfo &fileInfo);
    
    // Utility functions
    std::string getCurrentDateTime();
    std::string sanitizeFilename(const std::string &filename);
    std::string htmlEscape(const std::string &text);
};
