include(ExternalProject)
cmake_minimum_required(VERSION 3.10)

project(Lox VERSION 1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

include_directories(src)
set(SOURCE 
    src/main.c
    src/chunk.c
    src/memory.c
    src/debug.c
)

add_executable(${PROJECT_NAME}
    ${SOURCE}
)
