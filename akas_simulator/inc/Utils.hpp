// aka_simulator/inc/Utils.hpp
#pragma once

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include <elfio/elfio.hpp>
#include <string>

namespace Utils {

    int map_capstone_to_unicorn_reg(arm_reg capstone_reg);

    std::string formatHexBytes(const uint8_t *bytes, uint32_t size);

    std::string getCurrentTimestamp();

    bool findFunctionAddress(const std::string &elf_path, const std::string &function_name, uint32_t &address);

    bool findGlobalVariableAddress(const std::string &elf_path, const std::string &var_name, uint32_t &addr);
}