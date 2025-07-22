// src/elf_loader.cpp

#include "elf_loader.hpp"
#include <elfio/elfio.hpp>

bool ElfLoader::load(const std::string &elf_path)
{
    ELFIO::elfio elf_reader;
    if (!elf_reader.load(elf_path))
        return false;

    entry_point_ = elf_reader.get_entry();

    for (const auto &section : elf_reader.sections)
    {
        ELFIO::Elf_Half type = section->get_type();
        // We care about only SHT_PROGBITS and SHT_NOBITS sections
        // SHT_PROGBITS: contains data, code, etc.
        // SHT_NOBITS: represents uninitialized data (BSS)
        // Other types are not relevant for loading into memory
        // and can be ignored.
        if (type == ELFIO::SHT_PROGBITS || type == ELFIO::SHT_NOBITS)
        {
            Section sec;
            sec.name = section->get_name();
            sec.address = static_cast<uint32_t>(section->get_address());
            sec.size = static_cast<uint32_t>(section->get_size());
            sec.flags = static_cast<uint32_t>(section->get_flags());

            if (type == ELFIO::SHT_PROGBITS)
            {
                const char *data_ptr = section->get_data();
                if (data_ptr != nullptr && sec.size > 0)
                {
                    sec.data = std::vector<uint8_t>(data_ptr, data_ptr + sec.size);
                }
            }
            else if (type == ELFIO::SHT_NOBITS)
            {
                // BSS: allocated but not initialized data
                sec.data = std::vector<uint8_t>(sec.size, 0);
            }

            sections_.push_back(std::move(sec));
        }
    }

    return true;
}
