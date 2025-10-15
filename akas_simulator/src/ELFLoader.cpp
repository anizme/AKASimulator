// aka_simulator/src/ELFLoader.cpp

#include "ELFLoader.hpp"
#include "MemoryManager.hpp"
#include <elfio/elfio.hpp>
#include <iostream>
#include <cstdlib>
#include <sstream>

namespace STM32F103C8T6
{

    ELFLoader::ELFLoader(uc_engine *engine) : uc_engine_(engine)
    {
    }

    ELFLoader::~ELFLoader()
    {
        // backtrace_state cleanup is handled by the system
    }

    bool ELFLoader::loadELF(const std::string &elf_path, ELFInfo &elf_info)
    {
        std::cout << "[Load ELF] Loading ELF file: " << elf_path << std::endl;

        elf_info.file_path = elf_path;

        // Load segments and get entry point
        if (!loadSegments(elf_path, elf_info.entry_point, elf_info))
        {
            std::cerr << "Failed to load ELF segments" << std::endl;
            return false;
        }

        // Find function symbol
        if (!findMainSymbol(elf_path, elf_info.main_address))
        {
            std::cerr << "Failed to find main symbol" << std::endl;
            return false;
        }
        if (!findAkaWriterSymbol(elf_path, elf_info.aka_sim_writer_u32_address, elf_info.aka_sim_writer_u64_address))
        {
            std::cerr << "Failed to find aka_sim_writer symbols" << std::endl;
            return false;
        }

        std::cout << "ELF loaded successfully" << std::endl;
        std::cout << "Entry point: 0x" << std::hex << elf_info.entry_point << std::endl;
        std::cout << "Main address: 0x" << elf_info.main_address << std::dec << std::endl;

        return true;
    }

    bool ELFLoader::loadSegments(const std::string &elf_path, uint32_t &entry_point, ELFInfo& elf_info)
    {
        ELFIO::elfio reader;
        if (!reader.load(elf_path))
        {
            std::cerr << "Failed to load ELF file: " << elf_path << std::endl;
            return false;
        }

        if (reader.get_class() != ELFIO::ELFCLASS32)
        {
            std::cerr << "This is not a 32-bit ELF file (STM32 uses ELF32)!" << std::endl;
            return false;
        }

        entry_point = static_cast<uint32_t>(reader.get_entry());

        // Load program segments into memory
        for (int i = 0; i < reader.segments.size(); ++i)
        {
            const auto &segment = *reader.segments[i];

            if (segment.get_type() == ELFIO::PT_LOAD && segment.get_file_size() > 0)
            {
                uint64_t vaddr = segment.get_virtual_address();
                uint64_t size = segment.get_file_size();

                std::cout << "Loading segment " << i << ": 0x" << std::hex << vaddr
                          << " (size: 0x" << size << ")" << std::dec << std::endl;

                // Write segment data to emulated memory
                uc_err err = uc_mem_write(uc_engine_, vaddr, segment.get_data(), size);
                if (err != UC_ERR_OK)
                {
                    std::cerr << "Failed to write segment to memory: " << uc_strerror(err) << std::endl;
                    return false;
                }
            }
        }

        // Vector table setup
        for (const auto& sec : reader.sections)
        {
            if (sec->get_name() == ".isr_vector") {
                elf_info.vector_table_addr_ = static_cast<uint32_t>(sec->get_address());
                elf_info.vector_table_size_ = static_cast<uint32_t>(sec->get_size());

                std::cout << "Vector table found at 0x" << std::hex << elf_info.vector_table_addr_
                        << " size = 0x" << elf_info.vector_table_size_ << std::dec << std::endl;
                break;
            }
        }

        // Default vector table if not found
        if (elf_info.vector_table_size_ == 0) {
            elf_info.vector_table_addr_ = 0x08000000; // default Flash start
            elf_info.vector_table_size_ = 0x150;      // STM32F103C8T6: 16 + 68 entries
            std::cout << "Vector table not found in ELF, fallback size = 0x"
                    << std::hex << elf_info.vector_table_size_ << std::dec << std::endl;
        }
        
        return true;
    }

    bool ELFLoader::findMainSymbol(const std::string &elf_path, uint32_t &main_address)
    {
        return findFunctionAddress(elf_path, "main", main_address);
    }

    bool ELFLoader::findAkaWriterSymbol(const std::string &elf_path, uint32_t &address32, uint32_t &address64)
    {
        if (!findFunctionAddress(elf_path, "aka_sim_writer_u32", address32))
        {
            std::cerr << "Failed to find aka_sim_writer_u32 symbol" << std::endl;
            return false;
        }
        if (!findFunctionAddress(elf_path, "aka_sim_writer_u64", address64))
        {
            std::cerr << "Failed to find aka_sim_writer_u64 symbol" << std::endl;
            return false;
        }
        return true;
    }

    bool ELFLoader::findFunctionAddress(const std::string &elf_path, const std::string &func_name, uint32_t &addr)
    {
        ELFIO::elfio reader;
        if (!reader.load(elf_path))
            return false;

        ELFIO::section *symtab = nullptr;
        for (int i = 0; i < reader.sections.size(); ++i)
        {
            ELFIO::section *sec = reader.sections[i];
            if (sec->get_type() == ELFIO::SHT_SYMTAB)
            {
                symtab = sec;
                break;
            }
        }
        if (!symtab)
            return false;

        ELFIO::symbol_section_accessor symbols(reader, symtab);

        bool found = false;
        bool found_weak = false;
        uint32_t tmp_addr = 0;

        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j)
        {
            std::string name;
            ELFIO::Elf64_Addr value;
            ELFIO::Elf_Xword size;
            unsigned char bind, type, other;
            ELFIO::Elf_Half section_index;

            symbols.get_symbol(j, name, value, size, bind, type, section_index, other);

            if (name == func_name &&
                type == ELFIO::STT_FUNC &&
                section_index != ELFIO::SHN_UNDEF)
            {
                uint32_t aligned = static_cast<uint32_t>(value & ~1U);

                if (bind == ELFIO::STB_GLOBAL)
                {
                    addr = aligned;
                    return true;
                }
                else if (bind == ELFIO::STB_WEAK && !found_weak)
                {
                    tmp_addr = aligned;
                    found_weak = true;
                }
            }
        }

        if (found_weak)
        {
            addr = tmp_addr;
            return true;
        }
        return false;
    }

} // namespace STM32F103C8T6