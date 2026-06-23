if(NOT DEFINED MDH_BUILD_DIR)
    message(FATAL_ERROR "MDH_BUILD_DIR is required")
endif()
if(NOT DEFINED MDH_SOURCE_DIR)
    message(FATAL_ERROR "MDH_SOURCE_DIR is required")
endif()
if(NOT DEFINED MDH_INSTALL_DIR)
    message(FATAL_ERROR "MDH_INSTALL_DIR is required")
endif()
if(NOT DEFINED MDH_C_COMPILER)
    message(FATAL_ERROR "MDH_C_COMPILER is required")
endif()
if(NOT DEFINED MDH_MAKE_PROGRAM)
    message(FATAL_ERROR "MDH_MAKE_PROGRAM is required")
endif()
if(NOT DEFINED MDH_BUILD_CONFIG)
    message(FATAL_ERROR "MDH_BUILD_CONFIG is required")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${MDH_BUILD_DIR}" --config "${MDH_BUILD_CONFIG}" --prefix "${MDH_INSTALL_DIR}"
    RESULT_VARIABLE install_result
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "install failed: ${install_result}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${MDH_BUILD_DIR}/consumer-smoke"
    RESULT_VARIABLE remove_result
)
if(NOT remove_result EQUAL 0)
    message(FATAL_ERROR "consumer clean failed: ${remove_result}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -S "${MDH_SOURCE_DIR}/tests/consumer" -B "${MDH_BUILD_DIR}/consumer-smoke"
            "-DCMAKE_PREFIX_PATH=${MDH_INSTALL_DIR}"
            "-DCMAKE_C_COMPILER=${MDH_C_COMPILER}"
            "-DCMAKE_MAKE_PROGRAM=${MDH_MAKE_PROGRAM}"
    RESULT_VARIABLE configure_result
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "consumer configure failed: ${configure_result}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${MDH_BUILD_DIR}/consumer-smoke" --config "${MDH_BUILD_CONFIG}"
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "consumer build failed: ${build_result}")
endif()

if(WIN32)
    set(consumer_exe_config "${MDH_BUILD_DIR}/consumer-smoke/${MDH_BUILD_CONFIG}/microdh_consumer.exe")
    set(consumer_exe_root "${MDH_BUILD_DIR}/consumer-smoke/microdh_consumer.exe")
    if(EXISTS "${consumer_exe_config}")
        set(consumer_exe "${consumer_exe_config}")
    else()
        set(consumer_exe "${consumer_exe_root}")
    endif()
else()
    set(consumer_exe "${MDH_BUILD_DIR}/consumer-smoke/microdh_consumer")
endif()

execute_process(
    COMMAND "${consumer_exe}"
    RESULT_VARIABLE run_result
)
if(NOT run_result EQUAL 0)
    message(FATAL_ERROR "consumer run failed: ${run_result}")
endif()
