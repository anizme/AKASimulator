cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(AKAS_Test_Reporter)

include_directories(
    ${PROJECT_SOURCE_DIR}/inc
)

file(GLOB_RECURSE REPORTER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

add_executable(akas_reporter 
    ${REPORTER_SOURCES}
)



