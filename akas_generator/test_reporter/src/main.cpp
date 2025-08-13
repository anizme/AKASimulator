#include "TestReportGenerator.hpp"
#include <iostream>

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        std::cout << "Usage: " << argv[0] << " <test_case.json> <actuals.log> <code_line.log> [output_directory]" << std::endl;
        std::cout << "Example: " << argv[0] << " test_case.json actuals.log code_line.log test_report" << std::endl;
        return 1;
    }

    std::string testCaseJsonPath = argv[1];
    std::string actualsLogPath = argv[2];
    std::string codeLineLogPath = argv[3];
    std::string outputDir = "akas_working_space/test_report";

    TestReportGenerator generator(outputDir);

    if (generator.generateReport(testCaseJsonPath, actualsLogPath, codeLineLogPath))
    {
        generator.printStatistics();
        return 0;
    }
    else
    {
        std::cerr << "Failed to generate test report" << std::endl;
        return 1;
    }
}