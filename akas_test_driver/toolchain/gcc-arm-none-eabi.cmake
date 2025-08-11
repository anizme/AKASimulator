# Toolchain file for ARM Cortex-M3
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Cross compiler
set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)

# Bypass ABI checks because host couldnt run the target elf file
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
