// aka_simulator/inc/SimulationLogRefactor.hpp

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

/**
 * @brief A utility class for processing simulation log files.
 * 
 * This class reads a log file, keeps lines starting from the first line
 * containing "(main)", removes consecutive duplicate lines, and writes
 * the cleaned output to a new file.
 */
class SimulationLogRefactor
{
private:
    std::string inputFilePath;              ///< Path to the input log file
    std::string outputFileName;             ///< Name of the generated output file
    std::vector<std::string> logLines;      ///< Raw log lines read from input

    /**
     * @brief Reads the input file and stores lines into a vector.
     * 
     * The function begins collecting lines starting from the first line
     * containing "(main)".
     * 
     * @return true if the input file was successfully read and "(main)" was found, false otherwise.
     */
    bool readInputFile();

    /**
     * @brief Removes consecutive duplicate lines from the collected log lines.
     * 
     * @return A vector of unique lines after filtering.
     */
    std::vector<std::string> filterDuplicateLines();

public:
    /**
     * @brief Constructor that initializes the object with a given input file path.
     * 
     * @param inputPath Path to the input log file.
     */
    explicit SimulationLogRefactor(const std::string &inputPath);

    /**
     * @brief Executes the full log refactoring process.
     * 
     * Steps:
     *  1. Read and collect lines from the input file.
     *  2. Filter out consecutive duplicate lines.
     *  3. Write the cleaned lines to a new output file.
     * 
     * The output file will be named "<fileName>_simulation.log".
     * 
     * @param fileName Base name for the output file.
     * @return true if the process completes successfully, false otherwise.
     */
    bool process(const std::string &fileName);
};
