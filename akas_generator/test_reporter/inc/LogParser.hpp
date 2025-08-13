#pragma once

#include "ReportData.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>

using json = nlohmann::json;

class LogParser
{
public:
    static bool parseActualsLog(const std::string &actualsPath, const std::string &jsonPath, 
                               std::vector<ComparisonEntry> &comparisonResults);
    static bool parseCodeLineLog(const std::string &logPath, 
                                std::map<std::string, FileInfo> &fileInfos, 
                                ExecutionResult &execResult);

private:
    static std::vector<std::string> preprocessLog(const std::vector<std::string> &lines);
    static void parseCodeLine(const std::string &line, bool isErrorLine, 
                             std::map<std::string, FileInfo> &fileInfos, 
                             ExecutionResult &execResult);
    static std::string extractVariableFromSourceCode(const std::string &location, 
                                                     const std::string &actual, 
                                                     const std::string &expected, 
                                                     const json &testCaseJson);
    static ComparisonEntry parseVariableInfo(const std::string &varInfo, 
                                           const std::string &actual, 
                                           const std::string &expected, 
                                           const json &testCaseJson);
};

