// aka_simulator/src/ELFLoader.cpp

#include "ELFLoader.hpp"
#include <elfio/elfio.hpp>
#include <iostream>

namespace STM32F103C8T6 {

ELFLoader::ELFLoader(uc_engine* engine) : uc_engine_(engine) {
}

ELFLoader::~ELFLoader() {
    // backtrace_state cleanup is handled by the system
}

bool ELFLoader::loadELF(const std::string& elf_path, ELFInfo& elf_info) {
    std::cout << "Loading ELF file: " << elf_path << std::endl;

    elf_info.file_path = elf_path;

    // Load segments and get entry point
    if (!loadSegments(elf_path, elf_info.entry_point)) {
        std::cerr << "Failed to load ELF segments" << std::endl;
        return false;
    }

    // Find main symbol
    if (!findMainSymbol(elf_path, elf_info.main_address)) {
        std::cerr << "Failed to find main symbol" << std::endl;
        return false;
    }

    // Initialize backtrace for debugging
    elf_info.debug_state = initializeBacktrace(elf_path);
    if (!elf_info.debug_state) {
        std::cerr << "Warning: Failed to initialize backtrace state" << std::endl;
        // Not a fatal error, continue without debug info
    }

    std::cout << "ELF loaded successfully" << std::endl;
    std::cout << "Entry point: 0x" << std::hex << elf_info.entry_point << std::endl;
    std::cout << "Main address: 0x" << elf_info.main_address << std::dec << std::endl;

    return true;
}

bool ELFLoader::loadSegments(const std::string& elf_path, uint32_t& entry_point) {
    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        std::cerr << "Failed to load ELF file: " << elf_path << std::endl;
        return false;
    }

    if (reader.get_class() != ELFIO::ELFCLASS32) {
        std::cerr << "This is not a 32-bit ELF file (STM32 uses ELF32)!" << std::endl;
        return false;
    }

    entry_point = static_cast<uint32_t>(reader.get_entry());

    // Load program segments into memory
    for (int i = 0; i < reader.segments.size(); ++i) {
        const auto& segment = *reader.segments[i];

        if (segment.get_type() == ELFIO::PT_LOAD && segment.get_file_size() > 0) {
            uint64_t vaddr = segment.get_virtual_address();
            uint64_t size = segment.get_file_size();

            std::cout << "Loading segment " << i << ": 0x" << std::hex << vaddr
                      << " (size: 0x" << size << ")" << std::dec << std::endl;

            // Write segment data to emulated memory
            uc_err err = uc_mem_write(uc_engine_, vaddr, segment.get_data(), size);
            if (err != UC_ERR_OK) {
                std::cerr << "Failed to write segment to memory: " << uc_strerror(err) << std::endl;
                return false;
            }
        }
    }

    return true;
}

bool ELFLoader::findMainSymbol(const std::string& elf_path, uint32_t& main_address) {
    ELFIO::elfio reader;
    if (!reader.load(elf_path)) {
        return false;
    }

    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        if (sec->get_type() == ELFIO::SHT_SYMTAB) {
            const ELFIO::symbol_section_accessor symbols(reader, sec);
            for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
                std::string name;
                ELFIO::Elf64_Addr value;
                ELFIO::Elf_Xword size;
                unsigned char bind, type, other;
                ELFIO::Elf_Half section_index;

                symbols.get_symbol(j, name, value, size, bind, type, section_index, other);

                if (name == "main") {
                    main_address = static_cast<uint32_t>(value & ~1U);
                    std::cout << "Raw main address from ELF: 0x" << std::hex << value
                              << " | Aligned: 0x" << (value & ~1U) << std::dec << std::endl;
                    return true;
                }
            }
        }
    }

    return false;
}

backtrace_state* ELFLoader::initializeBacktrace(const std::string& elf_path) {
    backtrace_state* state = backtrace_create_state(elf_path.c_str(), 1, errorCallback, nullptr);
    
    if (state) {
        // Check for debugging information
        ELFIO::elfio reader;
        if (reader.load(elf_path)) {
            bool has_debug_info = false;
            for (int i = 0; i < reader.sections.size(); ++i) {
                if (reader.sections[i]->get_type() == ELFIO::SHT_PROGBITS &&
                    reader.sections[i]->get_name() == ".debug_info") {
                    has_debug_info = true;
                    break;
                }
            }
            if (!has_debug_info) {
                std::cerr << "Warning: ELF file may lack debugging information" << std::endl;
            }
        }
    }

    return state;
}

void ELFLoader::errorCallback(void* data, const char* msg, int errnum) {
    std::cerr << "libbacktrace error: " << msg << " (errnum=" << errnum << ")" << std::endl;
}

} // namespace STM32F103C8T6