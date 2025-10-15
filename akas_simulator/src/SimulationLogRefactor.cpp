#include "SimulationLogRefactor.hpp"

SimulationLogRefactor::SimulationLogRefactor(const std::string &inputPath)
    : inputFilePath(inputPath) {}

bool SimulationLogRefactor::readInputFile()
{
    std::ifstream inputFile(inputFilePath);

    if (!inputFile.is_open())
    {
        std::cerr << "Error: Cannot open input file: " << inputFilePath << std::endl;
        return false;
    }

    std::string line;
    bool foundMainStart = false;

    while (std::getline(inputFile, line))
    {
        if (!foundMainStart && line.find("(main)") != std::string::npos)
        {
            foundMainStart = true;
            logLines.push_back(line);
        }
        else if (foundMainStart)
        {
            logLines.push_back(line);
        }
    }

    inputFile.close();
    return foundMainStart;
}

std::vector<std::string> SimulationLogRefactor::filterDuplicateLines()
{
    std::vector<std::string> filteredLines;

    if (logLines.empty())
        return filteredLines;

    filteredLines.push_back(logLines[0]);

    for (size_t i = 1; i < logLines.size(); ++i)
    {
        if (logLines[i] != logLines[i - 1])
        {
            filteredLines.push_back(logLines[i]);
        }
    }

    return filteredLines;
}

bool SimulationLogRefactor::process(const std::string &fileName)
{
    outputFileName = fileName + "_simulation.log";

    if (!readInputFile())
    {
        std::cerr << "Error: Cannot find any line with (main)" << std::endl;
        return false;
    }

    std::vector<std::string> filteredLines = filterDuplicateLines();

    std::ofstream outputFile(outputFileName);
    if (!outputFile.is_open())
    {
        std::cerr << "Error: Cannot create output file: " << outputFileName << std::endl;
        return false;
    }

    for (const auto &line : filteredLines)
    {
        outputFile << line << std::endl;
    }

    outputFile.close();

    std::cout << "Success: Output file created at: " << outputFileName << std::endl;
    std::cout << "Total lines processed: " << filteredLines.size() << std::endl;

    return true;
}