# elf_builder/CMakeLists.txt
# This CMakeLists.txt is responsible for building the firmware ELF file.
cmake_minimum_required(VERSION 3.13)
project(elf_builder C CXX ASM)

# Set output
set(OUTPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/)
# Need debug info and no optimization for easier to mapping address to source code
set(CORTEX3_FLAGS -mcpu=cortex-m3 -mthumb -nostdlib -g -O0 -static -g3 -fno-inline -fno-common -fno-builtin)
set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/toolchain/stm32f103c8t6/linker.ld)
message(STATUS "Using linker script: ${LINKER_SCRIPT}")

file(GLOB_RECURSE SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/input_source/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/input_source/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/input_source/*.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/input_source/*.cxx
    ${CMAKE_CURRENT_SOURCE_DIR}/input_source/*.s
    ${CMAKE_CURRENT_SOURCE_DIR}/input_source/*.S
)
add_executable(firmware.elf ${SOURCES})

set_target_properties(firmware.elf PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}
)

target_compile_options(firmware.elf PRIVATE ${CORTEX3_FLAGS})
target_link_options(firmware.elf PRIVATE ${CORTEX3_FLAGS} -T${LINKER_SCRIPT})
