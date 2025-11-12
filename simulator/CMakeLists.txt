# Options
option(BUILD_TESTS "Build tests" ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Add I/O module (logging only for now)
add_subdirectory(src/io)

# Tests
if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_step1 tests/test_step1.cpp)
    target_link_libraries(test_step1 simulator_io)
    
    add_test(NAME Step1Test COMMAND test_step1)
endif()