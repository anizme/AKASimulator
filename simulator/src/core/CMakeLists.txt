# Find dependencies
# find_package(PkgConfig REQUIRED)
# pkg_check_modules(UNICORN REQUIRED unicorn)

# Core module library
add_library(simulator_core
    loader/ELFLoader.cpp
)

target_include_directories(simulator_core PUBLIC
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/elfio
    ${PROJECT_SOURCE_DIR}/lib/unicorn/include
    ${PROJECT_SOURCE_DIR}/lib/capstone/include
    ${PROJECT_SOURCE_DIR}/lib/libdwarf
)

# Link libraries
target_link_libraries(simulator_core PRIVATE 
    unicorn
    capstone
    dwarf
)

target_link_libraries(simulator_core PUBLIC
    simulator_io
    simulator_architecture
)