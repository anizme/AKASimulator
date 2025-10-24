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
        uint32_t main_addr;
        uint32_t akas_assert_u32_addr;
        uint32_t akas_assert_u64_addr;
        uint32_t aka_fCall_addr;
        uint32_t aka_mark_addr;
        uint32_t vector_table_addr_ = 0;
        uint32_t vector_table_size_ = 0;
        std::string file_path;
    };

    class ELFLoader
    {
    public:
        explicit ELFLoader(uc_engine *engine);
        ~ELFLoader();

        bool loadELF(const std::string &elf_path, ELFInfo &elf_info);

    private:
        uc_engine *uc_engine_;

        bool loadSegments(const std::string &elf_path, uint32_t &entry_point, ELFInfo &elf_info);
        bool findMainSymbol(const std::string &elf_path, uint32_t &main_addrs);
        bool findAkaUTSymbol(const std::string &elf_path,
                             uint32_t &address32, uint32_t &address64,
                             uint32_t &aka_fCall_addr, uint32_t &aka_mark);

        bool findFunctionAddress(const std::string &elf_path, const std::string &function_name, uint32_t &address);
        bool findGlobalVariableAddress(const std::string &elf_path,
                                       const std::string &var_name,
                                       uint32_t &addr);
    };

} // namespace STM32F103C8T6