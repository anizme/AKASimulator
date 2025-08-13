#include "JsonParser.hpp"
#include <iostream>
#include <fstream>

bool JsonParser::parseTestCaseJson(const std::string &jsonPath, TestCaseInfo &testCaseInfo)
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

json JsonParser::findVariableInJson(const json &root, const std::string &realName, const std::string &virtualName)
{
    return searchJsonNode(root, realName, virtualName);
}

json JsonParser::searchJsonNode(const json &node, const std::string &realName, const std::string &virtualName)
{
    if (node.is_object())
    {
        if (node.contains("name") && node.contains("virtual_name") &&
            node["name"].is_string() && node["virtual_name"].is_string() &&
            (node["name"] == realName || node["virtual_name"] == realName))
        {
            return node; 
        }
        for (const auto &item : node.items())
        {
            json result = searchJsonNode(item.value(), realName, virtualName);
            if (!result.is_null())
            {
                return result; 
            }
        }
    }
    else if (node.is_array())
    {
        for (const auto &item : node)
        {
            json result = searchJsonNode(item, realName, virtualName);
            if (!result.is_null())
            {
                return result;
            }
        }
    }
    return json(nullptr);
}