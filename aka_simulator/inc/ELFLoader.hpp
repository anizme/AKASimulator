// aka_simulator/inc/ELFLoader.hpp
#pragma once
#include <string>
#include <cstdint>
#include <unicorn/unicorn.h>

namespace STM32F103C8T6
{

    struct ELFInfo
    {
        uint32_t entry_point;
        uint32_t main_address;
        std::string file_path;
        std::string addr2line_command; // Command to call addr2line
    };

    class ELFLoader
    {
    public:
        explicit ELFLoader(uc_engine *engine);
        ~ELFLoader();

        bool loadELF(const std::string &elf_path, ELFInfo &elf_info);

    private:
        uc_engine *uc_engine_;

        bool loadSegments(const std::string &elf_path, uint32_t &entry_point);
        bool findMainSymbol(const std::string &elf_path, uint32_t &main_address);
        std::string setupAddr2LineCommand(const std::string &elf_path);
        bool checkAddr2LineAvailable();
        bool findFunctionAddress(const std::string &elf_path, const std::string &function_name, uint32_t &address);
    };

} // namespace STM32F103C8T6