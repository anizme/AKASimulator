// aka_simulator/inc/Utils.hpp
#pragma once

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include <string>

namespace Utils {

    int map_capstone_to_unicorn_reg(arm_reg capstone_reg);

    std::string formatHexBytes(const uint8_t *bytes, uint32_t size);

    std::string getCurrentTimestamp();
}