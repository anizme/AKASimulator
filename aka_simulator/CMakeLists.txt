include_directories(
    ${PROJECT_SOURCE_DIR}/lib/elfio
    ${PROJECT_SOURCE_DIR}/aka_simulator/inc
)

add_executable(stm32f103c8t6_emulator 
    src/main.cpp
    src/STM32F103C8T6Emulator.cpp
)

# Link Unicorn
target_link_libraries(stm32f103c8t6_emulator PRIVATE unicorn)