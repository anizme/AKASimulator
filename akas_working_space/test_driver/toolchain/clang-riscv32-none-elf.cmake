# Toolchain file for RISC-V 32-bit bare-metal using Clang
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv32)

# Use clang as compiler
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER clang)

# Clang target flags for RISC-V 32
set(RISCV_TARGET_FLAGS "--target=riscv32-none-elf -march=rv32imac -mabi=ilp32")

set(CMAKE_C_FLAGS_INIT "${RISCV_TARGET_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "${RISCV_TARGET_FLAGS}")
set(CMAKE_ASM_FLAGS_INIT "${RISCV_TARGET_FLAGS}")

# Prevent CMake from trying to run test executables
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
