// src/elf_loader.cpp

#include "elf_loader.hpp"
#include <elfio/elfio.hpp>

bool ElfLoader::load(const std::string &elf_path)
{
    ELFIO::elfio elf_reader;
    if (!elf_reader.load(elf_path))
        return false;

    entry_point_ = elf_reader.get_entry();

    for (int i = 0; i < elf_reader.segments.size(); ++i)
    {
        const ELFIO::segment *pseg = elf_reader.segments[i];

        // We only care about loadable segments (PT_LOAD)
        if (pseg->get_type() != ELFIO::PT_LOAD) {
            continue;
        }

        Segment seg;
        seg.virtual_address = static_cast<uint32_t>(pseg->get_virtual_address());
        seg.physical_address = static_cast<uint32_t>(pseg->get_physical_address());
        seg.size = static_cast<uint32_t>(pseg->get_memory_size());
        seg.file_size = static_cast<uint32_t>(pseg->get_file_size());
        seg.flags = static_cast<uint32_t>(pseg->get_flags());
        seg.alignment = static_cast<uint32_t>(pseg->get_align());

        // Get segment data
        const char *data = pseg->get_data();
        if (data != nullptr && seg.file_size > 0)
        {
            seg.data.assign(data, data + seg.file_size);

            // If memory size is larger than file size, pad with zeros
            if (seg.size > seg.file_size)
            {
                seg.data.resize(seg.size, 0);
            }
        }
        else if (seg.size > 0)
        {
            // For NOBITS sections (like .bss) in the segment
            seg.data.resize(seg.size, 0);
        }

        segments_.push_back(std::move(seg));
    }

    return true;
}
