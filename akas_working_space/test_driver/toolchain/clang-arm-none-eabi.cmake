# Toolchain file for ARM Cortex-M3 using Clang
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Use clang / clang++ as compiler
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER clang)

# Tell clang to cross-compile for ARM Cortex-M3
set(CLANG_TARGET_FLAGS "--target=arm-none-eabi -mcpu=cortex-m3 -mthumb")

set(CMAKE_C_FLAGS_INIT "${CLANG_TARGET_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "${CLANG_TARGET_FLAGS}")
set(CMAKE_ASM_FLAGS_INIT "${CLANG_TARGET_FLAGS}")

# Bypass ABI checks because host cannot run target ELF
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
