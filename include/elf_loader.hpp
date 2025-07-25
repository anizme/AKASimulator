// include/elf_loader.hpp

#pragma once
#include <string>
#include <vector>
#include <cstdint>

class ElfLoader
{
public:
    struct Segment
    {
        uint32_t virtual_address;  // Address to load into memory
        uint32_t physical_address; // Physical address (if different)
        uint32_t size;             // Size of segment in memory
        uint32_t file_size;        // Size of segment in file (may be smaller than memory size)
        std::vector<uint8_t> data; // Segment data
        uint32_t flags;            // Permission flags (R/W/X)
        uint32_t alignment;        // Alignment requirement
    };

    bool load(const std::string &elf_path);
    const std::vector<Segment> &get_segments() const { return segments_; }
    uint32_t get_entry_point() const { return entry_point_; }

private:
    std::vector<Segment> segments_;
    uint32_t entry_point_ = 0;
};