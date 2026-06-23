cmake_minimum_required(VERSION 3.16)
project(microdh VERSION 2.0.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(MDH_TOP_LEVEL ON)
else()
    set(MDH_TOP_LEVEL OFF)
endif()

if(MDH_TOP_LEVEL)
    include(CTest)
endif()

option(MDH_BUILD_TESTS "Build production black-box tests" ${MDH_TOP_LEVEL})
option(MDH_BUILD_INTERNAL_TESTS "Build internal instrumentation tests" ${MDH_TOP_LEVEL})
option(MDH_BUILD_DIFFERENTIAL_TESTS "Build differential oracle tests" OFF)
option(MDH_BUILD_FUZZERS "Build bounded fuzz smoke tests" OFF)
option(MDH_BUILD_EXAMPLES "Build examples" OFF)
option(MDH_BUILD_SLOW_TESTS "Build slow iteration test" OFF)
option(MDH_STRICT_WARNINGS "Enable strict project-local warnings" OFF)

find_package(OpenSSL QUIET)

add_library(microdh STATIC src/mdh.c)
add_library(microdh::microdh ALIAS microdh)
target_include_directories(microdh
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(microdh PUBLIC c_std_99)

add_library(microdh_testing_obj OBJECT src/mdh.c)
target_include_directories(microdh_testing_obj
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(microdh_testing_obj PRIVATE MDH_TESTING)
target_compile_features(microdh_testing_obj PRIVATE c_std_99)

function(mdh_apply_warnings target_name)
    if(MDH_STRICT_WARNINGS)
        if(MSVC)
            target_compile_options(${target_name} PRIVATE /W4 /WX)
        else()
            target_compile_options(${target_name} PRIVATE
                -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion
                -Wshadow -Wformat=2 -Wundef -Wcast-align -Wstrict-prototypes
                -Wmissing-prototypes -Wvla)
        endif()
    else()
        if(MSVC)
            target_compile_options(${target_name} PRIVATE /W4)
        else()
            target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    endif()
endfunction()

mdh_apply_warnings(microdh)
mdh_apply_warnings(microdh_testing_obj)

if(MDH_BUILD_TESTS)
    add_executable(mdh_tests tests/test_all.c)
    target_link_libraries(mdh_tests PRIVATE microdh)
    target_include_directories(mdh_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    mdh_apply_warnings(mdh_tests)
    add_test(NAME mdh_tests COMMAND $<TARGET_FILE:mdh_tests>)
endif()

if(MDH_BUILD_INTERNAL_TESTS)
    add_executable(mdh_internal_tests
        tests/test_internal.c
        $<TARGET_OBJECTS:microdh_testing_obj>)
    target_compile_definitions(mdh_internal_tests PRIVATE MDH_TESTING)
    target_include_directories(mdh_internal_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    mdh_apply_warnings(mdh_internal_tests)
    add_test(NAME mdh_internal_tests COMMAND $<TARGET_FILE:mdh_internal_tests>)
endif()

if(MDH_BUILD_DIFFERENTIAL_TESTS)
    add_executable(mdh_oracle_tests tests/test_oracle.c)
    target_link_libraries(mdh_oracle_tests PRIVATE microdh)
    target_include_directories(mdh_oracle_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    mdh_apply_warnings(mdh_oracle_tests)
    if(OpenSSL_FOUND)
        target_compile_definitions(mdh_oracle_tests PRIVATE MDH_HAVE_OPENSSL=1)
        target_link_libraries(mdh_oracle_tests PRIVATE OpenSSL::Crypto)
    else()
        target_compile_definitions(mdh_oracle_tests PRIVATE MDH_HAVE_OPENSSL=0)
    endif()
    add_test(NAME mdh_oracle_tests COMMAND $<TARGET_FILE:mdh_oracle_tests>)
    set_tests_properties(mdh_oracle_tests PROPERTIES LABELS "oracle" SKIP_RETURN_CODE 77)
endif()

if(MDH_BUILD_SLOW_TESTS)
    add_executable(mdh_slow_tests tests/test_slow.c)
    target_link_libraries(mdh_slow_tests PRIVATE microdh)
    target_include_directories(mdh_slow_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    mdh_apply_warnings(mdh_slow_tests)
    add_test(NAME mdh_slow_tests COMMAND $<TARGET_FILE:mdh_slow_tests>)
    set_tests_properties(mdh_slow_tests PROPERTIES LABELS "slow")
endif()

if(MDH_BUILD_FUZZERS)
    add_custom_target(mdh_fuzz_smoke COMMENT "Bounded deterministic fuzz smoke is embedded in mdh_tests")
endif()

if(MDH_BUILD_TESTS)
    add_test(
        NAME mdh_consumer_smoke
        COMMAND ${CMAKE_COMMAND}
            -DMDH_BUILD_DIR=${CMAKE_BINARY_DIR}
            -DMDH_SOURCE_DIR=${CMAKE_SOURCE_DIR}
            -DMDH_INSTALL_DIR=${CMAKE_BINARY_DIR}/_install
            -DMDH_BUILD_CONFIG=$<CONFIG>
            -DMDH_C_COMPILER=${CMAKE_C_COMPILER}
            -DMDH_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}
            -P ${CMAKE_SOURCE_DIR}/tests/consumer_smoke.cmake
    )
    set_tests_properties(mdh_consumer_smoke PROPERTIES LABELS "consumer")
endif()

set(MDH_PACKAGE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/microdh")

install(TARGETS microdh EXPORT microdhTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT microdhTargets
    FILE microdhTargets.cmake
    NAMESPACE microdh::
    DESTINATION ${MDH_PACKAGE_INSTALL_DIR}
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/microdhConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/microdhConfig.cmake
    INSTALL_DESTINATION ${MDH_PACKAGE_INSTALL_DIR}
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/microdhConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/microdhConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/microdhConfigVersion.cmake
    DESTINATION ${MDH_PACKAGE_INSTALL_DIR}
)

if(MDH_TOP_LEVEL)
    enable_testing()
endif()
