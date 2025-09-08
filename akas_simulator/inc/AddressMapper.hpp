#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

struct SourceLocation {
    std::string filename;
    int line = 0;
    int column = 0;
    std::string function_name;
    
    SourceLocation() = default;
    SourceLocation(const std::string& file, int ln, int col = 0, const std::string& func = "")
        : filename(file), line(ln), column(col), function_name(func) {}
    
    std::string toString() const {
        std::string result;
        if (!function_name.empty() && function_name != "??") {
            result += function_name + " at ";
        }
        result += filename + ":" + std::to_string(line);
        if (column > 0) {
            result += ":" + std::to_string(column);
        }
        return result;
    }
    
    bool isValid() const { 
        return !filename.empty() && filename != "??" && line > 0; 
    }
};

struct AddressRange {
    uintptr_t start_addr;
    uintptr_t end_addr;    // Exclusive end
    SourceLocation location;
    
    AddressRange(uintptr_t start, uintptr_t end, const SourceLocation& loc)
        : start_addr(start), end_addr(end), location(loc) {}
    
    bool contains(uintptr_t addr) const {
        return addr >= start_addr && addr < end_addr;
    }
};

class AddressMapper {
public:
    // Constructor - builds mapping from ELF file
    explicit AddressMapper(const std::string& elf_file_path);
    
    // Get source location for given PC address
    // Fast O(log n) lookup using binary search
    std::optional<SourceLocation> getSourceLocation(uintptr_t pc_address) const;
    
    // Check if mapper was initialized successfully
    bool isInitialized() const { return initialized_; }
    
    // Get last error message
    const std::string& getLastError() const { return last_error_; }
    
    // Get statistics
    size_t getMappingCount() const { return address_ranges_.size(); }
    
    // Save/load precomputed mapping to/from binary cache file
    bool saveCache(const std::string& cache_file) const;
    bool loadCache(const std::string& cache_file);

private:
    // Build mapping by calling dwarfdump and parsing output
    bool buildMappingFromDwarfdump(const std::string& elf_file);
    
    // Parse dwarfdump output line by line
    bool parseDwarfdumpOutput(const std::string& output);
    
    // Parse a single line from dwarfdump output
    std::optional<std::pair<uintptr_t, SourceLocation>> parseDwarfdumpLine(const std::string& line);
    
    // Convert parsed entries to ranges (merge consecutive addresses with same location)
    void buildRanges();
    
    // Binary search helper
    std::vector<AddressRange>::const_iterator findRangeContaining(uintptr_t address) const;
    
private:
    bool initialized_ = false;
    std::string last_error_;
    
    // Sorted vector of address ranges for fast binary search
    std::vector<AddressRange> address_ranges_;
    
    // Temporary storage during parsing
    std::vector<std::pair<uintptr_t, SourceLocation>> raw_entries_;
};