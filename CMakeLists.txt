cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(AKASimulator)


# Unicorn need to built as static
set(UNICORN_BUILD_SHARED OFF CACHE BOOL "Build static Unicorn lib")

# Add Unicorn subdirectory
add_subdirectory(lib/unicorn)

add_subdirectory(aka_simulator)
