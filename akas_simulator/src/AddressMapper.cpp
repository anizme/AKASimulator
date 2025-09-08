#include "AddressMapper.hpp"
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iostream>
#include <regex>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>

AddressMapper::AddressMapper(const std::string& elf_file_path) {
    // Try to load from cache first
    std::string cache_file = elf_file_path + ".addr_cache";
    if (loadCache(cache_file)) {
        initialized_ = true;
        return;
    }
    
    // Build mapping from ELF file
    if (buildMappingFromDwarfdump(elf_file_path)) {
        initialized_ = true;
        // Save cache for next time
        saveCache(cache_file);
    }
}

std::optional<SourceLocation> AddressMapper::getSourceLocation(uintptr_t pc_address) const {
    if (!initialized_) {
        return std::nullopt;
    }
    
    auto it = findRangeContaining(pc_address);
    if (it != address_ranges_.end()) {
        return it->location;
    }
    
    return std::nullopt;
}

bool AddressMapper::buildMappingFromDwarfdump(const std::string& elf_file) {
    // Try different dwarfdump tools in order of preference
    std::vector<std::string> dwarfdump_commands = {
        "llvm-dwarfdump --debug-line \"" + elf_file + "\"",
        "dwarfdump -l \"" + elf_file + "\"",
        "readelf -wl \"" + elf_file + "\""
    };
    
    std::string output;
    bool success = false;
    
    for (const auto& cmd : dwarfdump_commands) {
        std::cout << "Trying: " << cmd << std::endl;
        
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            continue;
        }
        
        char buffer[4096];
        output.clear();
        
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        
        int status = pclose(pipe);
        if (status == 0 && !output.empty()) {
            success = true;
            std::cout << "Successfully got output from: " << cmd << std::endl;
            break;
        }
    }
    
    if (!success) {
        last_error_ = "Failed to run any dwarfdump tool. Install llvm-dwarfdump, dwarfdump, or use readelf.";
        return false;
    }
    
    // Parse the output
    if (!parseDwarfdumpOutput(output)) {
        return false;
    }
    
    // Convert to ranges
    buildRanges();
    
    std::cout << "Built " << address_ranges_.size() << " address ranges" << std::endl;
    return !address_ranges_.empty();
}

bool AddressMapper::parseDwarfdumpOutput(const std::string& output) {
    std::istringstream stream(output);
    std::string line;
    
    raw_entries_.clear();
    
    // Different regex patterns for different tools
    std::vector<std::regex> patterns = {
        // llvm-dwarfdump pattern: 0x0000000000401234     15      0      1   0             0  is_stmt
        std::regex(R"(0x([0-9a-fA-F]+)\s+(\d+)\s+(\d+).*)"),
        
        // dwarfdump pattern: 0x00401234  [  15, 5] NS uri: "/path/file.cpp"
        std::regex(R"(0x([0-9a-fA-F]+)\s+\[\s*(\d+),\s*(\d+)\].*uri:\s*\"([^\"]+)\")"),
        
        // readelf pattern: more complex, need to parse differently
        std::regex(R"(.*)")  // Fallback pattern
    };
    
    int parsed_count = 0;
    
    while (std::getline(stream, line)) {
        auto entry = parseDwarfdumpLine(line);
        if (entry.has_value()) {
            raw_entries_.push_back(entry.value());
            parsed_count++;
        }
    }
    
    std::cout << "Parsed " << parsed_count << " address entries" << std::endl;
    
    if (parsed_count == 0) {
        last_error_ = "No address entries found in dwarfdump output";
        return false;
    }
    
    // Sort by address
    std::sort(raw_entries_.begin(), raw_entries_.end(),
              [](const auto& a, const auto& b) {
                  return a.first < b.first;
              });
    
    return true;
}

std::optional<std::pair<uintptr_t, SourceLocation>> AddressMapper::parseDwarfdumpLine(const std::string& line) {
    // Try llvm-dwarfdump format first
    std::regex llvm_pattern(R"(0x([0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\w+\s*(.*)?)");
    std::smatch match;
    
    if (std::regex_search(line, match, llvm_pattern)) {
        uintptr_t addr = std::stoull(match[1].str(), nullptr, 16);
        int line_num = std::stoi(match[2].str());
        int col_num = std::stoi(match[3].str());
        
        // llvm-dwarfdump doesn't include filename in each line, 
        // we need to track the current file from "file_names[" lines
        static std::string current_file = "unknown";
        
        // Look for file_names entries
        std::regex file_pattern(R"(file_names\[\s*\d+\]:\s*name:\s*\"([^\"]+)\")");
        std::smatch file_match;
        if (std::regex_search(line, file_match, file_pattern)) {
            current_file = file_match[1].str();
            return std::nullopt; // This line is just file info, not an address entry
        }
        
        if (line_num > 0) {
            SourceLocation loc(current_file, line_num, col_num);
            return std::make_pair(addr, loc);
        }
    }
    
    // Try dwarfdump format
    std::regex dwarf_pattern(R"(0x([0-9a-fA-F]+)\s+\[\s*(\d+),\s*(\d+)\].*uri:\s*\"([^\"]+)\")");
    if (std::regex_search(line, match, dwarf_pattern)) {
        uintptr_t addr = std::stoull(match[1].str(), nullptr, 16);
        int line_num = std::stoi(match[2].str());
        int col_num = std::stoi(match[3].str());
        std::string filename = match[4].str();
        
        if (line_num > 0) {
            SourceLocation loc(filename, line_num, col_num);
            return std::make_pair(addr, loc);
        }
    }
    
    return std::nullopt;
}

void AddressMapper::buildRanges() {
    address_ranges_.clear();
    
    if (raw_entries_.empty()) {
        return;
    }
    
    // Build ranges by grouping consecutive addresses with same source location
    uintptr_t range_start = raw_entries_[0].first;
    SourceLocation current_loc = raw_entries_[0].second;
    
    for (size_t i = 1; i < raw_entries_.size(); ++i) {
        uintptr_t addr = raw_entries_[i].first;
        const SourceLocation& loc = raw_entries_[i].second;
        
        // If location changed, create a range for the previous location
        if (loc.filename != current_loc.filename || 
            loc.line != current_loc.line ||
            loc.column != current_loc.column) {
            
            // Create range from range_start to current address
            address_ranges_.emplace_back(range_start, addr, current_loc);
            
            // Start new range
            range_start = addr;
            current_loc = loc;
        }
    }
    
    // Add final range (extend to a reasonable end address)
    uintptr_t final_end = raw_entries_.back().first + 16; // Assume max 16 bytes per instruction
    address_ranges_.emplace_back(range_start, final_end, current_loc);
    
    // Sort ranges by start address (should already be sorted, but just to be sure)
    std::sort(address_ranges_.begin(), address_ranges_.end(),
              [](const AddressRange& a, const AddressRange& b) {
                  return a.start_addr < b.start_addr;
              });
}

std::vector<AddressRange>::const_iterator AddressMapper::findRangeContaining(uintptr_t address) const {
    // Binary search for the range containing the address
    auto it = std::upper_bound(address_ranges_.begin(), address_ranges_.end(), address,
                               [](uintptr_t addr, const AddressRange& range) {
                                   return addr < range.start_addr;
                               });
    
    if (it != address_ranges_.begin()) {
        --it;
        if (it->contains(address)) {
            return it;
        }
    }
    
    return address_ranges_.end();
}

bool AddressMapper::saveCache(const std::string& cache_file) const {
    std::ofstream file(cache_file, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Write number of ranges
    size_t count = address_ranges_.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    // Write each range
    for (const auto& range : address_ranges_) {
        file.write(reinterpret_cast<const char*>(&range.start_addr), sizeof(range.start_addr));
        file.write(reinterpret_cast<const char*>(&range.end_addr), sizeof(range.end_addr));
        
        // Write filename length and content
        size_t filename_len = range.location.filename.length();
        file.write(reinterpret_cast<const char*>(&filename_len), sizeof(filename_len));
        file.write(range.location.filename.c_str(), filename_len);
        
        // Write line and column
        file.write(reinterpret_cast<const char*>(&range.location.line), sizeof(range.location.line));
        file.write(reinterpret_cast<const char*>(&range.location.column), sizeof(range.location.column));
        
        // Write function name length and content
        size_t func_len = range.location.function_name.length();
        file.write(reinterpret_cast<const char*>(&func_len), sizeof(func_len));
        file.write(range.location.function_name.c_str(), func_len);
    }
    
    return file.good();
}

bool AddressMapper::loadCache(const std::string& cache_file) {
    std::ifstream file(cache_file, std::ios::binary);
    if (!file) {
        return false;
    }
    
    address_ranges_.clear();
    
    // Read number of ranges
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!file || count == 0) {
        return false;
    }
    
    address_ranges_.reserve(count);
    
    // Read each range
    for (size_t i = 0; i < count; ++i) {
        uintptr_t start_addr, end_addr;
        file.read(reinterpret_cast<char*>(&start_addr), sizeof(start_addr));
        file.read(reinterpret_cast<char*>(&end_addr), sizeof(end_addr));
        
        // Read filename
        size_t filename_len;
        file.read(reinterpret_cast<char*>(&filename_len), sizeof(filename_len));
        std::string filename(filename_len, '\0');
        file.read(&filename[0], filename_len);
        
        // Read line and column
        int line, column;
        file.read(reinterpret_cast<char*>(&line), sizeof(line));
        file.read(reinterpret_cast<char*>(&column), sizeof(column));
        
        // Read function name
        size_t func_len;
        file.read(reinterpret_cast<char*>(&func_len), sizeof(func_len));
        std::string func_name(func_len, '\0');
        file.read(&func_name[0], func_len);
        
        if (!file) {
            address_ranges_.clear();
            return false;
        }
        
        SourceLocation loc(filename, line, column, func_name);
        address_ranges_.emplace_back(start_addr, end_addr, loc);
    }
    
    std::cout << "Loaded " << address_ranges_.size() << " ranges from cache" << std::endl;
    return true;
}