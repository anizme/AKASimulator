// include/elf_loader.hpp

#pragma once
#include <string>
#include <vector>
#include <cstdint>

class ElfLoader
{
public:
    struct Section
    {
        std::string name; // ".text", ".data"
        uint32_t address; // Address that loaded onto RAM/Flash
        uint32_t size;    // Size of section 
        std::vector<uint8_t> data;
        uint32_t flags; // permission: R/W/X, using for map into Unicorn
    };

    bool load(const std::string &elf_path);
    const std::vector<Section> &get_sections() const { return sections_; }
    uint32_t get_entry_point() const { return entry_point_; }

private:
    std::vector<Section> sections_;
    uint32_t entry_point_ = 0;
};