// aka_simulator/src/ExecutionLogger.cpp

#include "ExecutionLogger.hpp"
#include "MemoryMap.hpp"
#include "Utils.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <cstring>
#include <filesystem>
#include <regex>

namespace STM32F103C8T6
{

    ExecutionLogger::~ExecutionLogger()
    {
        close();
    }

    bool ExecutionLogger::initialize(const std::string &log_file_path, const std::string &elf_path,
                                     uint32_t entry_point, const std::string &trace_code_command)
    {
        elf_path_ = elf_path;
        trace_code_command_ = trace_code_command;
        instruction_count_ = 0;
    {
            std::filesystem::path logPath(log_file_path);
            std::filesystem::path logDir = logPath.parent_path();

            std::error_code ec;
            std::filesystem::create_directories(logDir, ec);
            if (ec)
            {
                std::cerr << "[Warn]: Failed to create directory for log file: "
                        << logDir << " (" << ec.message() << ")" << std::endl;
            }
    }
        log_file_.open(log_file_path);
        if (!log_file_.is_open())
        {
            std::cerr << "Failed to open log file: " << log_file_path << std::endl;
            return false;
        }

        std::string trace_file_path = generateTraceFilePath(log_file_path);
        trace_file_.open(trace_file_path);
        if (!trace_file_.is_open())
        {
            std::cerr << "Failed to open log file: " << trace_file_path << std::endl;
            trace_file_ << "[";
            return false;
        }

        std::string testPath_file_path = generateTestPathFilePath(log_file_path);
        test_path_file_.open(testPath_file_path);
        if (!test_path_file_.is_open())
        {
            std::cerr << "Failed to open log file: " << testPath_file_path << std::endl;
            return false;
        }

        std::cout << "Log file created: " << log_file_path << std::endl;
        writeHeader(entry_point);
        return true;
    }

        std::string ExecutionLogger::generateTraceFilePath(const std::string &filePath)
    {
        std::filesystem::path path(filePath);
        std::string fileName = path.stem().string(); // "name"
        std::filesystem::path parentPath = path.parent_path(); // "r1/r2/simulation"

        std::filesystem::path grandParent = parentPath.parent_path(); // "r1/r2"
        std::filesystem::path outputDir = grandParent / "execution-results";

        std::error_code ec;
        std::filesystem::create_directories(outputDir, ec);

        std::filesystem::path outputPath = outputDir / (fileName + ".trc");
        return outputPath.string();
    }

    std::string ExecutionLogger::generateTestPathFilePath(const std::string &filePath)
    {
        std::filesystem::path path(filePath);
        std::string fileName = path.stem().string(); // "name"
        std::filesystem::path parentPath = path.parent_path(); // "r1/r2/simulation"

        std::filesystem::path grandParent = parentPath.parent_path(); // "r1/r2"
        std::filesystem::path outputDir = grandParent / "test-paths";

        std::error_code ec;
        std::filesystem::create_directories(outputDir, ec);

        std::filesystem::path outputPath = outputDir / (fileName + ".tp");
        return outputPath.string();
    }


    void ExecutionLogger::logInstructionRaw(uint64_t address, const uint8_t *instruction_bytes, uint32_t size)
    {
        if (!log_file_.is_open())
        {
            return;
        }

        // Use a osstringstream to capture backtrace output
        std::ostringstream oss;
        oss << "Instruction: 0x" << std::hex << std::setfill('0') << std::setw(8) << address << ": ";
        oss << Utils::formatHexBytes(instruction_bytes, size);

        appendSourceInfo(oss, address);
        writeLogLine(oss.str());
    }

    void ExecutionLogger::logAkaMark(uint64_t address) {
        if (!test_path_file_.is_open())
        {
            return;
        }

        std::string line = readSourceLineAt(previousSourceInfo_);

        // Tìm vị trí của /*...*/
        std::smatch match;
        if (std::regex_search(line, match, std::regex(R"(/\*(.*?)\*/)")))
        {
            test_path_file_ << match[1].str() << "\n";
            test_path_file_.flush();
        }
    }

    void ExecutionLogger::logInstructionAsm(uint64_t address, const char *mnemonic, const char *op_str)
    {
        if (!log_file_.is_open())
        {
            return;
        }

        // Format: [ADDRESS] MNEMONIC OPERANDS
        std::ostringstream oss;
        oss << "[0x" << std::hex << std::setfill('0') << std::setw(8) << address << "] ";
        oss << std::setfill(' ') << std::left << std::setw(8) << mnemonic;

        if (op_str && strlen(op_str) > 0)
        {
            oss << " " << op_str;
        }

        appendSourceInfo(oss, address);
        writeLogLine(oss.str());
    }

    void ExecutionLogger::appendSourceInfo(std::ostringstream &oss, uint64_t address)
    {
        oss << "\n\t# CodePos:";
        if (!trace_code_command_.empty())
        {
            previousSourceInfo_ = getSourceInfo(address);
            oss << dumpSourceInfo(previousSourceInfo_);
        }
        else
        {
            oss << "unknown (llvm-symbolier not available)";
        }
    }

    void ExecutionLogger::writeLogLine(const std::string &line)
    {
        log_file_ << line << "\n";

        if (++instruction_count_ % 100 == 0)
        {
            log_file_.flush();
        }
    }

    void ExecutionLogger::logError(const std::string &message)
    {
        if (log_file_.is_open())
        {
            log_file_ << "# ERROR: " << message << std::endl;
            log_file_.flush();
        }
        std::cerr << "[LOG] " + message << std::endl;
    }

    void ExecutionLogger::logInfo(const std::string &message, uint64_t address)
    {
        if (log_file_.is_open())
        {
            log_file_ << message << " at 0x" << std::hex << address << std::dec << std::endl;
            log_file_.flush();
        }
    }

    std::string ExecutionLogger::dumpSourceInfo(const SourceInfo &info)
    {
        std::string str;
        if (!info.filename.empty() && info.filename != "??")
        {
            str.append(info.filename).append(":").append(std::to_string(info.line_number)).append(":").append(std::to_string(info.col_number));
            if (!info.function.empty() && info.function != "??")
            {
                str.append(" (").append(info.function).append(")");
            }
        }
        else
        {
            str.append("unknown (no debug info)");
        }
        return str;
    }

    std::string ExecutionLogger::dumpSourceInfoOnlyLineOfCode(const SourceInfo &info)
    {
        std::string str;
        if (!info.filename.empty() && info.filename != "??")
        {
            str.append(info.filename).append(":").append(std::to_string(info.line_number));
        }
        else
        {
            str.append("unknown (no debug info)");
        }
        return str;
    }

    void ExecutionLogger::logAssert(const std::string &assertion, uint64_t address)
    {
        if (!trace_file_.is_open()) {
            return;
        }

        std::string line = readSourceLineAt(previousSourceInfo_);

        // Parse hàm assert: ví dụ akas_assert_u32(arr_len, EXPECTED_arr_len);
        std::smatch match;
        if (std::regex_search(line, match,
            std::regex(R"(\((\s*\w+\s*),\s*(\w+)\s*\))")))
        {
            std::string actualName   = match[1];
            std::string expectedName = match[2];

            // Parse assertion string
            std::smatch values;
            std::regex_search(assertion, values,
                std::regex(R"(# ACTUAL: (\d+), # EXPECTED: (\d+), # FCALL: (\d+))"));
            
            std::ostringstream oss;
            oss << "{\n"
                << "\"tag\": \"Aka function calls: " << values[3].str() << "\",\n"
                << "\"actualName\": \"" << actualName << "\",\n"
                << "\"actualVal\": \"" << values[1].str() << "\",\n"
                << "\"expectedName\": \"" << expectedName << "\",\n"
                << "\"expectedVal\": \"" << values[2].str() << "\"\n"
                << "}";
            traces_.push_back(oss.str());
        }
    }

    void ExecutionLogger::endTraceFile() {
        trace_file_ << "[";
        for (size_t i = 0; i < traces_.size(); ++i) {
            trace_file_ << traces_[i];
            if (i != traces_.size() - 1)
                trace_file_ << ",\n";
        }
        trace_file_ << "]";
    }

    std::string ExecutionLogger::readSourceLineAt(const SourceInfo &info)
    {
        std::ifstream src(info.filename);
        if (!src.is_open()) {
            std::cerr << "[WARN] Cannot open source file: " << info.filename << std::endl;
            return "";
        }

        std::string line = "";
        for (int i = 1; i <= info.line_number && std::getline(src, line); ++i) {
            // dừng tại dòng cần thiết
        }

        if (line.empty()) {
            std::cerr << "[WARN] Empty or invalid line at "
                    << info.filename << ":" << info.line_number << std::endl;
            return "";
        }

        // Nếu col_number hợp lệ -> cắt phần sau đó
        if (info.col_number > 0 && info.col_number < (int)line.size()) {
            line = line.substr(info.col_number);
        }

        return line;
    }

    void ExecutionLogger::close()
    {
        if (log_file_.is_open())
        {
            log_file_.close();
        }
    }

    void ExecutionLogger::writeHeader(uint32_t entry_point)
    {
        log_file_ << "# STM32F103C8T6 Emulation Log" << std::endl;
        log_file_ << "# ELF File: " << elf_path_ << std::endl;
        log_file_ << "# Start Time: " << Utils::getCurrentTimestamp() << std::endl;
        log_file_ << "# Entry Point: 0x" << std::hex << entry_point << std::dec << std::endl;
        log_file_ << "# Memory Layout:" << std::endl;
        log_file_ << "# \tFlash: 0x" << std::hex << MemoryMap::FLASH_BASE << " - 0x"
                  << (MemoryMap::FLASH_BASE + MemoryMap::FLASH_SIZE - 1) << std::endl;
        log_file_ << "# \tSRAM:  0x" << MemoryMap::SRAM_BASE << " - 0x"
                  << (MemoryMap::SRAM_BASE + MemoryMap::SRAM_SIZE - 1) << std::dec << std::endl;
        log_file_ << "# Format: ADDRESS: FILE:LINE (FUNCTION)" << std::endl;
        log_file_ << "#" << std::endl;
        log_file_ << std::endl;
    }

    SourceInfo ExecutionLogger::getSourceInfo(uint64_t address)
    {
        // Check cache first
        auto it = address_cache_.find(address);
        if (it != address_cache_.end())
        {
            return it->second;
        }
        // Not in cache, call trace code tool
        std::string output = executeMapping(address);
        SourceInfo info = parseMappingOutput(output);

        // Cache the result (but limit cache size to prevent memory issues)
        if (address_cache_.size() < 10000)
        { // Limit cache to 10k entries
            address_cache_[address] = info;
        }

        return info;
    }

    std::string ExecutionLogger::executeMapping(uint64_t address)
    {
        if (trace_code_command_.empty())
        {
            return "";
        }

        // Create the command with the address
        std::stringstream cmd_ss;
        cmd_ss << trace_code_command_ << " 0x" << std::hex << address;
        std::string command = cmd_ss.str();

        // Execute the command and capture output
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

        if (!pipe)
        {
            std::cerr << "Failed to execute trace code tool command: " << command << std::endl;
            return "";
        }

        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr)
        {
            result += buffer;
        }
        return result;
    }

    SourceInfo ExecutionLogger::parseMappingOutput(const std::string &output)
    {
        SourceInfo info;
        info.filename = "??";
        info.function = "??";
        info.line_number = 0;
        info.col_number = 0;

        if (output.empty())
        {
            return info;
        }

        std::istringstream stream(output);
        std::string line;

        // llvm-symbolizer output format:
        // function_name\n
        // file:line:col\n
        // (có thể có thêm lines cho inlined functions nếu dùng --inlines)

        // First line is function name
        if (std::getline(stream, line))
        {
            if (!line.empty() && line != "??")
            {
                info.function = line;
                // Remove trailing newline/carriage return
                info.function.erase(std::remove(info.function.begin(), info.function.end(), '\n'), info.function.end());
                info.function.erase(std::remove(info.function.begin(), info.function.end(), '\r'), info.function.end());
            }
        }

        // Second line is file:line:col
        if (std::getline(stream, line))
        {
            if (!line.empty() && line != "??:0:0")
            {
                // Remove trailing newline/carriage return
                line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
                line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());

                // Parse file:line:col format
                size_t first_colon = line.find(':');
                if (first_colon != std::string::npos)
                {
                    info.filename = line.substr(0, first_colon);

                    size_t second_colon = line.find(':', first_colon + 1);
                    if (second_colon != std::string::npos)
                    {
                        try
                        {
                            // Extract line number
                            std::string line_str = line.substr(first_colon + 1, second_colon - first_colon - 1);
                            info.line_number = std::stoi(line_str);

                            // Extract column number
                            std::string col_str = line.substr(second_colon + 1);
                            info.col_number = std::stoi(col_str);
                        }
                        catch (const std::exception &)
                        {
                            info.line_number = 0;
                            info.col_number = 0;
                        }
                    }
                    else
                    {
                        // Fallback: only line number available
                        try
                        {
                            info.line_number = std::stoi(line.substr(first_colon + 1));
                        }
                        catch (const std::exception &)
                        {
                            info.line_number = 0;
                        }
                    }
                }
                else
                {
                    // No colon found, use whole line as filename
                    info.filename = line;
                }
            }
        }
        return info;
    }

} // namespace STM32F103C8T6