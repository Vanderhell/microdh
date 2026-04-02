cmake_minimum_required(VERSION 3.16)
project(microdh VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic)

add_library(microdh STATIC src/mdh.c)
target_include_directories(microdh PUBLIC include)

option(MDH_BUILD_TESTS "Build tests" ON)
if(MDH_BUILD_TESTS)
    enable_testing()
    add_executable(mdh_tests tests/test_all.c src/mdh.c)
    target_include_directories(mdh_tests PRIVATE include tests)
    add_test(NAME mdh_tests COMMAND mdh_tests)
endif()
