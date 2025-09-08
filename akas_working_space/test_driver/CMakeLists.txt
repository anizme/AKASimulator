# elf_builder/CMakeLists.txt
# This CMakeLists.txt is responsible for building the firmware ELF file.
cmake_minimum_required(VERSION 3.13)
project(elf_builder C CXX ASM)

# Set output
set(OUTPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/)

# Need debug info and no optimization for easier to mapping address to source code
set(CORTEX3_FLAGS 
    --target=arm-none-eabi
    -mcpu=cortex-m3 
    -mthumb 
    -nostdlib 
    -O0 
    -static 
    -g3 
    -fno-inline 
    -fno-common 
    -fno-builtin
    -gcolumn-info)

set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/toolchain/stm32f103c8t6/linker.ld)
message(STATUS "Using linker script: ${LINKER_SCRIPT}")

file(GLOB_RECURSE SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/akas_source/startup.s
)
# Add test driver main
set(TEST_DRIVER
    ${CMAKE_CURRENT_SOURCE_DIR}/test_driver_uut.c
)

add_executable(firmware.elf
    ${SOURCES}
    ${TEST_DRIVER}
)

set_target_properties(firmware.elf PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}
)

target_compile_options(firmware.elf PRIVATE ${CORTEX3_FLAGS})
target_link_options(firmware.elf PRIVATE ${CORTEX3_FLAGS} -T${LINKER_SCRIPT})
