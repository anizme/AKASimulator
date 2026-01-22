#pragma once

#include "simulator/Types.hpp"
#include "io/logging/ILogger.hpp"
#include <string>
#include <map>
#include <memory>

namespace Simulator
{

    /**
     * @brief Wrapper for llvm-symbolizer
     *
     * Resolves addresses to source code locations.
     * Caches results to avoid repeated subprocess calls.
     */
    class Symbolizer
    {
    public:
        /**
         * @brief Constructor
         * @param binary_path Path to ELF binary
         * @param logger Logger for errors
         */
        Symbolizer(const std::string &binary_path, LoggerPtr logger);

        /**
         * @brief Resolve address to source location
         * @param address Memory address
         * @return Source info (or empty if not found)
         */
        SourceInfo resolve(Address address);

        /**
         * @brief Clear cache
         */
        void clearCache() { cache_.clear(); }

        /**
         * @brief Get cache size
         */
        size_t getCacheSize() const { return cache_.size(); }

    private:
        std::string binary_path_;
        LoggerPtr logger_;
        std::map<Address, SourceInfo> cache_;

        // Execute llvm-symbolizer command
        std::string executeCommand(Address address);

        // Parse llvm-symbolizer output
        SourceInfo parseOutput(const std::string &output);
    };

} // namespace Simulator