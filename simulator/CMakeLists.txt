# Options
option(BUILD_TESTS "Build tests" ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Add modules
add_subdirectory(src/io)
add_subdirectory(src/architecture)

# Tests
if(BUILD_TESTS)
    enable_testing()
    
    # Step 1 test
    add_executable(test_step1 tests/test_step1.cpp)
    target_link_libraries(test_step1 simulator_io)
    add_test(NAME Step1Test COMMAND test_step1)
    
    # Step 2 test
    add_executable(test_step2 tests/test_step2.cpp)
    target_link_libraries(test_step2 
        simulator_io
        simulator_architecture
    )
    add_test(NAME Step2Test COMMAND test_step2)
endif()