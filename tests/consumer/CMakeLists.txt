cmake_minimum_required(VERSION 3.16)
project(microdh_consumer C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(microdh CONFIG REQUIRED)

add_executable(microdh_consumer main.c)
target_link_libraries(microdh_consumer PRIVATE microdh::microdh)
