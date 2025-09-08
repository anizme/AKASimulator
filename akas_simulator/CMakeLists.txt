include_directories(
    ${PROJECT_SOURCE_DIR}/lib/elfio
    ${PROJECT_SOURCE_DIR}/akas_simulator/inc
)

file(GLOB_RECURSE SIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

add_executable(akas_emulator 
    ${SIM_SOURCES}
)

# Link libraries
target_link_libraries(akas_emulator PRIVATE 
    unicorn
    capstone
    dwarf
)