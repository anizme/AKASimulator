#pragma once

#include <string>
#include <vector>
#include <set>

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
    bool success = false;
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
