# I/O module library
add_library(simulator_io
    logging/ConsoleLogger.cpp
    logging/FileLogger.cpp
)

target_include_directories(simulator_io PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)