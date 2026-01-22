# Architecture module library
add_library(simulator_architecture
    ArchitectureFactory.cpp
)

target_include_directories(simulator_architecture PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(simulator_architecture PUBLIC
    simulator_io  # For logging if needed
)