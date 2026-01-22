#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <ctime>

namespace Simulator
{
    namespace Utils
    {

        /**
         * @brief Format value as hex string
         */
        inline std::string formatHex(uint64_t value, size_t width = 8)
        {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::setfill('0') << std::setw(width) << value;
            return ss.str();
        }

        /**
         * @brief Format bytes as hex string
         */
        inline std::string formatBytes(const uint8_t *bytes, size_t size)
        {
            std::ostringstream ss;
            ss << std::hex << std::setfill('0');
            for (size_t i = 0; i < size; ++i)
            {
                ss << std::setw(2) << static_cast<int>(bytes[i]);
                if (i < size - 1)
                    ss << " ";
            }
            return ss.str();
        }

        /**
         * @brief Trim whitespace from string
         */
        inline std::string trim(const std::string &str)
        {
            size_t first = str.find_first_not_of(" \t\n\r");
            if (first == std::string::npos)
                return "";
            size_t last = str.find_last_not_of(" \t\n\r");
            return str.substr(first, last - first + 1);
        }

        /**
         * @brief Convert string to lowercase
         */
        inline std::string toLower(const std::string &str)
        {
            std::string result = str;
            std::transform(result.begin(), result.end(), result.begin(), ::tolower);
            return result;
        }

        /**
         * @brief Split string by delimiter
         */
        inline std::vector<std::string> split(const std::string &str, char delimiter)
        {
            std::vector<std::string> tokens;
            std::stringstream ss(str);
            std::string token;
            while (std::getline(ss, token, delimiter))
            {
                tokens.push_back(token);
            }
            return tokens;
        }

        /**
         * @brief Check if string starts with prefix
         */
        inline bool startsWith(const std::string &str, const std::string &prefix)
        {
            return str.size() >= prefix.size() &&
                   str.compare(0, prefix.size(), prefix) == 0;
        }

        /**
         * @brief Check if string ends with suffix
         */
        inline bool endsWith(const std::string &str, const std::string &suffix)
        {
            return str.size() >= suffix.size() &&
                   str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        inline std::string getCurrentTimestamp()
        {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);

            std::tm tm = *std::localtime(&time);

            char buffer[32];
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);

            return std::string(buffer);
        }

    } // namespace Utils
} // namespace Simulator