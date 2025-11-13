#pragma once

#include <string>
#include <filesystem>

namespace Simulator
{
    namespace Utils
    {

        /**
         * @brief Check if file exists
         */
        inline bool fileExists(const std::string &path)
        {
            return std::filesystem::exists(path);
        }

        /**
         * @brief Get file extension
         */
        inline std::string getFileExtension(const std::string &path)
        {
            return std::filesystem::path(path).extension().string();
        }

        /**
         * @brief Get filename without path
         */
        inline std::string getFileName(const std::string &path)
        {
            return std::filesystem::path(path).filename().string();
        }

        /**
         * @brief Get directory from path
         */
        inline std::string getDirectory(const std::string &path)
        {
            return std::filesystem::path(path).parent_path().string();
        }

        /**
         * @brief Create directory (and parents if needed)
         */
        inline bool createDirectory(const std::string &path)
        {
            std::error_code ec;
            return std::filesystem::create_directories(path, ec);
        }

        /**
         * @brief Get absolute path
         */
        inline std::string getAbsolutePath(const std::string &path)
        {
            return std::filesystem::absolute(path).string();
        }

    } // namespace Utils
} // namespace Simulator