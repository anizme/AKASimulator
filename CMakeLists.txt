cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(AKASimulator)

# Unicorn need to built as static
set(UNICORN_BUILD_SHARED OFF CACHE BOOL "Build static Unicorn lib")

# Add Unicorn subdirectory
add_subdirectory(lib/unicorn)
add_subdirectory(lib/capstone)
add_subdirectory(lib/libdwarf)

add_subdirectory(simulator)

# Options
option(BUILD_TESTS "Build tests" ON)

# Tests
if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_step1 simulator/tests/test_step1.cpp)
    target_link_libraries(test_step1 simulator_io)
    add_test(NAME Step1Test COMMAND test_step1)
    
    add_executable(test_step2 simulator/tests/test_step2.cpp)
    target_link_libraries(test_step2 
        simulator_io
        simulator_architecture
    )
    add_test(NAME Step2Test COMMAND test_step2)
    
    add_executable(test_step3_1 simulator/tests/test_step3_1_elfloader.cpp)
    target_link_libraries(test_step3_1
        simulator_core
    )
    add_test(NAME Step3_1Test COMMAND test_step3_1)
endif()