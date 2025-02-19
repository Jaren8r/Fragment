cmake_minimum_required(VERSION 3.22)
project(Fragment C)

set(CMAKE_C_STANDARD 17)

add_library(Fragment MODULE main.c curl.h util.h)

add_subdirectory(vendor/minhook)
target_link_libraries(Fragment minhook)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()