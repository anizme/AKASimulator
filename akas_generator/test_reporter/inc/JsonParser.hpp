#pragma once

#include "ReportData.hpp"
#include <nlohmann/json.hpp>
#include <string>

using json = nlohmann::json;

class JsonParser
{
public:
    static bool parseTestCaseJson(const std::string &jsonPath, TestCaseInfo &testCaseInfo);
    static json findVariableInJson(const json &root, const std::string &realName, const std::string &virtualName);
    
private:
    static json searchJsonNode(const json &node, const std::string &realName, const std::string &virtualName);
};

