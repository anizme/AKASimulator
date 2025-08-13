#include "LogParser.hpp"
#include "JsonParser.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>

bool LogParser::parseActualsLog(const std::string &actualsPath, const std::string &jsonPath, 
                               std::vector<ComparisonEntry> &comparisonResults)
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

bool LogParser::parseCodeLineLog(const std::string &logPath, 
                                std::map<std::string, FileInfo> &fileInfos, 
                                ExecutionResult &execResult)
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
            parseCodeLine(prevLine, true, fileInfos, execResult); // Mark as error line
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
        parseCodeLine(lines[i], false, fileInfos, execResult);
    }

    return true;
}

std::vector<std::string> LogParser::preprocessLog(const std::vector<std::string> &lines)
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

void LogParser::parseCodeLine(const std::string &line, bool isErrorLine, 
                             std::map<std::string, FileInfo> &fileInfos, 
                             ExecutionResult &execResult)
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

std::string LogParser::extractVariableFromSourceCode(const std::string &location, 
                                                    const std::string &actual, 
                                                    const std::string &expected, 
                                                    const json &testCaseJson)
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

ComparisonEntry LogParser::parseVariableInfo(const std::string &varInfo, 
                                            const std::string &actual, 
                                            const std::string &expected, 
                                            const json &testCaseJson)
{
    ComparisonEntry entry;

    size_t pipePos = varInfo.find('|');
    if (pipePos == std::string::npos)
        return entry;

    std::string realVar = varInfo.substr(0, pipePos);
    std::string virtualVar = varInfo.substr(pipePos + 1);
    
    // Find the corresponding variable in JSON
    auto varNode = JsonParser::findVariableInJson(testCaseJson, realVar, virtualVar);
    if (varNode.is_null())
    {
        std::cerr << "[Warning] Variable not found in JSON: " << realVar << " (" << virtualVar << ")" << std::endl;
        return entry; // Skip if variable not found
    }

    entry.paramName = realVar;
    // TODO: should be change when return value is not primitive type
    if (realVar == "AKA_ACTUAL_OUTPUT") {
        entry.paramName = varNode["name"];
    }
    entry.paramType = varNode.value("dataType", "unknown");
    entry.actualValue = actual;
    entry.expectedValue = expected;
    entry.matches = (actual == expected);
    entry.fullPath = realVar;

    return entry;
}