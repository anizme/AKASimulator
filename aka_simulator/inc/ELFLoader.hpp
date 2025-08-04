// aka_simulator/inc/ELFLoader.hpp
#pragma once
#include <string>
#include <cstdint>
#include <unicorn/unicorn.h>
#include <backtrace.h>

namespace STM32F103C8T6 {

struct ELFInfo {
    uint32_t entry_point;
    uint32_t main_address;
    std::string file_path;
    backtrace_state* debug_state;
};

class ELFLoader {
public:
    explicit ELFLoader(uc_engine* engine);
    ~ELFLoader();

    bool loadELF(const std::string& elf_path, ELFInfo& elf_info);

private:
    uc_engine* uc_engine_;

    bool loadSegments(const std::string& elf_path, uint32_t& entry_point);
    bool findMainSymbol(const std::string& elf_path, uint32_t& main_address);
    backtrace_state* initializeBacktrace(const std::string& elf_path);

    static void errorCallback(void* data, const char* msg, int errnum);
};

} // namespace STM32F103C8T6