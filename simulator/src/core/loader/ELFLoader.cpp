#include "ELFLoader.hpp"
#include "io/utils/FileUtils.hpp"
#include "io/utils/StringUtils.hpp"
#include <elfio/elfio.hpp>
#include <iostream>

namespace Simulator
{

    ELFLoader::ELFLoader(uc_engine *uc, LoggerPtr logger)
        : uc_(uc), logger_(logger)
    {
    }

    Result<BinaryInfo> ELFLoader::load(const std::string &elf_path)
    {
        LOG_INFO_F(logger_) << "Loading ELF file: " << elf_path;

        // Check if file exists
        if (!Utils::fileExists(elf_path))
        {
            return Result<BinaryInfo>::Error("ELF file not found: " + elf_path);
        }

        BinaryInfo info;
        info.file_path = elf_path;

        // Load segments
        if (!loadSegments(elf_path, info))
        {
            return Result<BinaryInfo>::Error("Failed to load ELF segments");
        }

        // Find symbols
        if (!findSymbols(elf_path, info))
        {
            return Result<BinaryInfo>::Error("Failed to find required symbols");
        }

        LOG_INFO_F(logger_) << "ELF loaded successfully";
        LOG_INFO_F(logger_) << "  Entry point: " << Utils::formatHex(info.entry_point);
        LOG_INFO_F(logger_) << "  Main address: " << Utils::formatHex(info.main_address);

        return Result<BinaryInfo>::Success(info);
    }

    bool ELFLoader::loadSegments(const std::string &elf_path, BinaryInfo &info)
    {
        ELFIO::elfio reader;

        if (!reader.load(elf_path))
        {
            LOG_ERROR(logger_, "Failed to open ELF file");
            return false;
        }

        // Check ELF class
        if (reader.get_class() != ELFIO::ELFCLASS32)
        {
            LOG_ERROR(logger_, "Not a 32-bit ELF file (expected ELF32)");
            return false;
        }

        // Get entry point
        info.entry_point = static_cast<Address>(reader.get_entry());

        // Load PT_LOAD segments
        for (int i = 0; i < reader.segments.size(); ++i)
        {
            const auto &segment = *reader.segments[i];

            if (segment.get_type() == ELFIO::PT_LOAD && segment.get_file_size() > 0)
            {
                Address vaddr = segment.get_virtual_address();
                Size size = segment.get_file_size();

                LOG_DEBUG_F(logger_) << "Loading segment " << i
                                     << ": " << Utils::formatHex(vaddr)
                                     << " (size: " << size << " bytes)";

                // Write segment data to Unicorn memory
                uc_err err = uc_mem_write(uc_, vaddr, segment.get_data(), size);
                if (err != UC_ERR_OK)
                {
                    LOG_ERROR_F(logger_) << "Failed to write segment: " << uc_strerror(err);
                    return false;
                }
            }
        }

        // Find vector table
        for (const auto &sec : reader.sections)
        {
            if (sec->get_name() == ".isr_vector")
            {
                info.vector_table_address = static_cast<Address>(sec->get_address());
                info.vector_table_size = static_cast<Size>(sec->get_size());

                LOG_DEBUG_F(logger_) << "Vector table: "
                                     << Utils::formatHex(info.vector_table_address)
                                     << " (size: " << info.vector_table_size << ")";
                break;
            }
        }

        // Default vector table if not found
        if (info.vector_table_size == 0)
        {
            info.vector_table_address = 0x08000000; // Flash start
            info.vector_table_size = 0x150;         // Default size
            LOG_DEBUG(logger_, "Vector table not found, using defaults");
        }

        return true;
    }

    bool ELFLoader::findSymbols(const std::string &elf_path, BinaryInfo &info)
    {
        // Find main
        if (!findFunctionAddress(elf_path, "main", info.main_address))
        {
            LOG_ERROR(logger_, "Failed to find 'main' symbol");
            return false;
        }

        // Find AKAS_assert_u32 (optional)
        if (!findFunctionAddress(elf_path, "AKAS_assert_u32", info.akas_assert_u32_address))
        {
            LOG_WARNING(logger_, "AKAS_assert_u32 not found (skipping)");
            info.akas_assert_u32_address = 0;
        }

        // Find AKAS_assert_u64 (optional)
        if (!findFunctionAddress(elf_path, "AKAS_assert_u64", info.akas_assert_u64_address))
        {
            LOG_WARNING(logger_, "AKAS_assert_u64 not found (skipping)");
            info.akas_assert_u64_address = 0;
        }

        // Find AKA_mark (optional)
        if (!findFunctionAddress(elf_path, "AKA_mark", info.aka_mark_address))
        {
            LOG_WARNING(logger_, "AKA_mark not found (skipping)");
            info.aka_mark_address = 0;
        }

        // Find AKA_fCall variable (optional)
        if (!findGlobalVariableAddress(elf_path, "AKA_fCall", info.aka_fcall_address))
        {
            LOG_WARNING(logger_, "AKA_fCall variable not found (skipping)");
            info.aka_fcall_address = 0;
        }

        return true;
    }

    bool ELFLoader::findFunctionAddress(const std::string &elf_path,
                                        const std::string &func_name,
                                        Address &addr)
    {
        ELFIO::elfio reader;
        if (!reader.load(elf_path))
        {
            return false;
        }

        // Find symbol table
        ELFIO::section *symtab = nullptr;
        for (int i = 0; i < reader.sections.size(); ++i)
        {
            auto sec = reader.sections[i];
            if (sec->get_type() == ELFIO::SHT_SYMTAB)
            {
                symtab = sec;
                break;
            }
        }

        if (!symtab)
        {
            return false;
        }

        ELFIO::symbol_section_accessor symbols(reader, symtab);

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

                // Clear Thumb bit for ARM
                addr = static_cast<Address>(value & ~1U);
                return true;
            }
        }

        return false;
    }

    bool ELFLoader::findGlobalVariableAddress(const std::string &elf_path,
                                              const std::string &var_name,
                                              Address &addr)
    {
        ELFIO::elfio reader;
        if (!reader.load(elf_path))
        {
            return false;
        }

        // Find symbol table
        ELFIO::section *symtab = nullptr;
        for (int i = 0; i < reader.sections.size(); ++i)
        {
            auto sec = reader.sections[i];
            if (sec->get_type() == ELFIO::SHT_SYMTAB)
            {
                symtab = sec;
                break;
            }
        }

        if (!symtab)
        {
            return false;
        }

        ELFIO::symbol_section_accessor symbols(reader, symtab);

        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j)
        {
            std::string name;
            ELFIO::Elf64_Addr value;
            ELFIO::Elf_Xword size;
            unsigned char bind, type, other;
            ELFIO::Elf_Half section_index;

            symbols.get_symbol(j, name, value, size, bind, type, section_index, other);

            if (name == var_name &&
                type == ELFIO::STT_OBJECT &&
                section_index != ELFIO::SHN_UNDEF)
            {

                addr = static_cast<Address>(value);
                return true;
            }
        }

        return false;
    }

} // namespace Simulator