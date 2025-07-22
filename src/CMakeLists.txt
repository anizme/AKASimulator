# Include thư viện ELFIO (header-only)
include_directories(
    ${PROJECT_SOURCE_DIR}/lib/elfio
    ${PROJECT_SOURCE_DIR}/include
)

# Thêm executable
add_executable(stm32_emulator 
    main.cpp
    elf_loader.cpp
    simulator.cpp
)

# Link Unicorn
target_link_libraries(stm32_emulator PRIVATE unicorn)