include_directories(
    ${PROJECT_SOURCE_DIR}/lib/elfio
    ${PROJECT_SOURCE_DIR}/aka_simulator/inc
)

file(GLOB_RECURSE SIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

add_executable(stm32f103c8t6_emulator 
    ${SIM_SOURCES}
)

# Link Unicorn
target_link_libraries(stm32f103c8t6_emulator PRIVATE unicorn)
target_link_libraries(stm32f103c8t6_emulator PRIVATE backtrace)