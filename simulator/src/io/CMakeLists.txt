add_library(simulator_io
    logging/ConsoleLogger.cpp
    logging/FileLogger.cpp
    utils/Symbolizer.cpp
    writers/SimulationLogWriter.cpp
    writers/TraceFileWriter.cpp
    writers/TestPathWriter.cpp
)

target_include_directories(simulator_io PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../
)