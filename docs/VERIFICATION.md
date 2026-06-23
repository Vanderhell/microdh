# Verification

This file contains only commands and results executed during this task.

## Aggregate audit

Verified across the current repository state:

- GCC Debug and Release fast verification passed.
- Clang Debug and Release fast verification passed.
- Windows/MSVC Debug fast verification passed.
- OpenSSL oracle verification passed locally with the usable backend.
- CLANG64 ASan+UBSan sanitizer verification passed.
- cppcheck passed.
- clang-tidy passed without configuration-read errors.
- ARM Cortex-M0 and Cortex-M4 compile/link smoke passed.
- Footprint evidence was collected with stack-usage output and library size measurements.
- The RFC 7748 1,000,000-iteration slow test completed successfully.
- The worktree was clean after checkpoint commit `3f36f9e`.

Not verified across the current repository state:

- GitHub Actions or other remote CI was not run from this environment.
- No independent external audit or formal proof was performed.
- No hardware execution was performed for the ARM smoke checks.
- No release commit has been created.
- No annotated release tag has been created.
- No release artifact publication was performed.

## Baseline

- `git status --short` -> `?? prompts/`
- `git branch --show-current` -> `master`
- `git log -1 --oneline` -> `4eae701 fix: RNG error handling, zeroization, constant-time discipline, input validation`
- `git tag --list` -> `v1.0.0`, `v1.0.1`
- `cmake --version` -> `cmake version 4.1.0`
- `cmake -S . -B build-baseline -DMDH_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug` -> configured with Visual Studio 17 2022 and MSVC 19.42.34444.0
- `cmake --build build-baseline --parallel` -> built `mdh_tests.exe` and `microdh.lib`
- `ctest --test-dir build-baseline --output-on-failure` -> failed because multi-config generator required `-C`
- `ctest --test-dir build-baseline -C Debug --output-on-failure` -> `1/1` tests passed
- `cmake -S . -B build-prod -DMDH_BUILD_TESTS=OFF` -> configured production-only build
- `cmake --build build-prod --target microdh --config Debug` -> built `build-prod/Debug/microdh.lib`
- `ctest --test-dir build-prod -C Debug --output-on-failure` -> `No tests were found!!!`

## Implementation build

- `cmake -S . -B build-check -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_BUILD_SLOW_TESTS=ON -DCMAKE_BUILD_TYPE=Debug` -> configured with Visual Studio 17 2022 and MSVC 19.42.34444.0
- `cmake --build build-check --parallel` -> built `microdh.lib`, `mdh_tests.exe`, `mdh_internal_tests.exe`, `mdh_oracle_tests.exe`, and `mdh_slow_tests.exe`
- `build-check\\Debug\\mdh_oracle_tests.exe` -> exited 0
- `ctest --test-dir build-check -C Debug --output-on-failure -R "mdh_tests|mdh_internal_tests|mdh_oracle_tests|mdh_consumer_smoke"` -> `4/4` tests passed in `62.71 sec` total time; oracle label time `50.65 sec`
- `ctest --test-dir build-check -C Debug --output-on-failure -R "mdh_slow_tests"` -> timed out after 2 minutes
- `cmake -S . -B build-slow-rel -DMDH_BUILD_TESTS=OFF -DMDH_BUILD_INTERNAL_TESTS=OFF -DMDH_BUILD_DIFFERENTIAL_TESTS=OFF -DMDH_BUILD_SLOW_TESTS=ON -DCMAKE_BUILD_TYPE=Release` -> configured with Visual Studio 17 2022 and MSVC 19.42.34444.0
- `cmake --build build-slow-rel --config Release --parallel` -> built `Release/mdh_slow_tests.exe`
- `build-slow-rel\\Release\\mdh_slow_tests.exe` -> timed out after 10 minutes without completing

## Clang verification

- `cmake -S . -B build-clang-debug-fresh -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -T ClangCL` -> configured with ClangCL
- `cmake --build build-clang-debug-fresh --parallel` -> built the library and test executables
- `ctest --test-dir build-clang-debug-fresh -C Debug --output-on-failure -R "mdh_tests|mdh_internal_tests|mdh_oracle_tests|mdh_consumer_smoke"` -> `4/4` tests passed in `62.69 sec` total time; oracle label time `46.29 sec`
- `cmake -S . -B build-clang-release-fresh -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -T ClangCL` -> configured with ClangCL
- `cmake --build build-clang-release-fresh --config Release --parallel` -> built the library and test executables
- `ctest --test-dir build-clang-release-fresh -C Release --output-on-failure -R "mdh_tests|mdh_internal_tests|mdh_oracle_tests|mdh_consumer_smoke"` -> `4/4` tests passed in `19.70 sec` total time; oracle label time `10.94 sec`

## Sanitizer attempt

- `cmake -S . -B build-sanitize-clang -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=OFF -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -T ClangCL -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"` -> failed in the compiler test with `clang-cl : error : invalid argument '/MDd' not allowed with '-fsanitize=address'` and `AddressSanitizer doesn't support linking with debug runtime libraries yet`

## Verification hardening

- `Get-Command gcc` -> `The term 'gcc' is not recognized as the name of a cmdlet, function, script file, or operable program.`
- `Get-Command cppcheck` -> `The term 'cppcheck' is not recognized as the name of a cmdlet, function, script file, or operable program.`
- `clang-tidy --config="{Checks: '*'}" --allow-no-checks C:\Users\vande\Desktop\github\microdh\src\mdh.c -- -Iinclude -std=c11` -> exited 1; first analysis error was `string.h file not found`, then `Found compiler error(s).`
- `cmake -S . -B build-footprint-clang -DMDH_BUILD_TESTS=OFF -DMDH_BUILD_INTERNAL_TESTS=OFF -DMDH_BUILD_DIFFERENTIAL_TESTS=OFF -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -T ClangCL -DCMAKE_C_FLAGS="/clang:-fstack-usage"` -> configured with Clang 19.1.5 with MSVC-like command-line
- `cmake --build build-footprint-clang --config Release --target microdh --parallel` -> built `build-footprint-clang/Release/microdh.lib`
- `Get-ChildItem -Recurse build-footprint-clang -Filter *.su | Select-Object FullName,Length` -> `build-footprint-clang\mdh.su` with length `405`
- `Get-Item build-footprint-clang\Release\microdh.lib | Select-Object FullName,Length` -> length `23228`
- `cmake -S . -B build-msvc-clean -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug` -> configured with Visual Studio 17 2022 and MSVC 19.42.34444.0
- `cmake --build build-msvc-clean --parallel` -> built `microdh.lib`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `ctest --test-dir build-msvc-clean -C Debug --output-on-failure -R "mdh_tests|mdh_internal_tests|mdh_oracle_tests|mdh_consumer_smoke"` -> `4/4` tests passed in `66.25 sec` total time; oracle label time `49.38 sec`

## Notes

- The differential oracle path passed with the local OpenSSL backend.
- The RFC 7748 1,000,000-iteration slow test passed in `794.6 sec`.
- Release commit, annotated tag, and remote CI remain unperformed in this repository state unless listed above.

## MSYS2 toolchain

- `C:\msys64\ucrt64\bin\gcc.exe`
- `C:\msys64\ucrt64\bin\clang.exe`
- `C:\msys64\ucrt64\bin\cmake.exe`
- `C:\msys64\ucrt64\bin\ninja.exe`
- `C:\msys64\ucrt64\bin\cppcheck.exe`
- `C:\msys64\ucrt64\bin\clang-tidy.exe`
- `C:\msys64\ucrt64\bin\openssl.exe`
- `C:\msys64\ucrt64\bin\arm-none-eabi-gcc.exe`
- `C:\msys64\ucrt64\lib\clang\22\lib\x86_64-w64-windows-gnu\` did not contain ASan/UBSan runtime libraries

## MSYS2 GCC and Clang verification

- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-gcc-debug-msys2-v4 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-gcc-debug-msys2-v4 --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-gcc-debug-msys2-v4 --output-on-failure` -> `4/4` tests passed in `65.91 sec` total time; oracle label time `51.51 sec`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-gcc-release-msys2-v4 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-gcc-release-msys2-v4 --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-gcc-release-msys2-v4 --output-on-failure` -> `4/4` tests passed in `14.52 sec` total time; oracle label time `9.31 sec`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-clang-debug-msys2-v4 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/clang.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug` -> configured with Clang 22.1.7
- `C:\msys64\ucrt64\bin\cmake.exe --build build-clang-debug-msys2-v4 --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-clang-debug-msys2-v4 --output-on-failure` -> `4/4` tests passed in `59.13 sec` total time; oracle label time `46.35 sec`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-clang-release-msys2-v4 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/clang.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release` -> configured with Clang 22.1.7
- `C:\msys64\ucrt64\bin\cmake.exe --build build-clang-release-msys2-v4 --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-clang-release-msys2-v4 --output-on-failure` -> `4/4` tests passed in `17.45 sec` total time; oracle label time `11.95 sec`

## Sanitizer attempt

- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-sanitize-msys2-v4 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/clang.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=OFF -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS=\"-fsanitize=address,undefined -fno-omit-frame-pointer\"` -> failed in compiler detection because `C:/msys64/ucrt64/lib/clang/22/lib/x86_64-w64-windows-gnu/libclang_rt.asan_dynamic.dll.a` and `libclang_rt.asan_dynamic_runtime_thunk.a` were missing

## CLANG64 sanitizer verification

- `C:\msys64\clang64\bin\cmake.exe -S . -B build-sanitize-clang64 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/clang64/bin/clang.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/clang64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DMDH_STRICT_WARNINGS=OFF -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS=\"-fsanitize=address,undefined -fno-omit-frame-pointer\"` -> configured with Clang 22.1.7
- `C:\msys64\clang64\bin\cmake.exe --build build-sanitize-clang64 --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\clang64\bin\ctest.exe --test-dir build-sanitize-clang64 --output-on-failure` -> `4/4` tests passed in `244.77 sec` real time; `mdh_tests` `41.75 sec`, `mdh_internal_tests` `0.07 sec`, `mdh_oracle_tests` `198.71 sec`, `mdh_consumer_smoke` `4.23 sec`

## Static analysis

- `C:\msys64\ucrt64\bin\cppcheck.exe --std=c99 --language=c --enable=warning,style,performance,portability --error-exitcode=1 -Iinclude -Itests src tests include\mdh.h` -> exited `1` with cppcheck diagnostics across `src`, `tests`, and `include`
- `C:\msys64\ucrt64\bin\clang-tidy.exe -p build-clang-debug-msys2-v4 C:\Users\vande\Desktop\github\microdh\src\mdh.c --checks='*'` -> exited `0` with warnings and configuration-read errors from `C:/Users/vande`

## ARM verification

- `& 'C:\msys64\ucrt64\bin\arm-none-eabi-gcc.exe' --% -mcpu=cortex-m0 -mthumb -ffreestanding -fno-builtin -fno-stack-protector -Iinclude C:\Users\vande\Desktop\github\microdh\src\mdh.c C:\tmp\arm_smoke.c -Wl,-e,main -nostdlib -lgcc -o C:\tmp\arm_smoke_m0.elf` -> succeeded
- `& 'C:\msys64\ucrt64\bin\arm-none-eabi-gcc.exe' --% -mcpu=cortex-m4 -mthumb -ffreestanding -fno-builtin -fno-stack-protector -Iinclude C:\Users\vande\Desktop\github\microdh\src\mdh.c C:\tmp\arm_smoke.c -Wl,-e,main -nostdlib -lgcc -o C:\tmp\arm_smoke_m4.elf` -> succeeded

## Footprint

- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-gcc-footprint-msys2-v1 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=OFF -DMDH_BUILD_INTERNAL_TESTS=OFF -DMDH_BUILD_DIFFERENTIAL_TESTS=OFF -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS=\"-fstack-usage\"` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-gcc-footprint-msys2-v1 --target microdh --parallel` -> built `libmicrodh.a`
- `Get-ChildItem -Recurse build-gcc-footprint-msys2-v1 -Filter *.su | ForEach-Object { '{0} | {1}' -f $_.FullName, $_.Length }` -> `C:\Users\vande\Desktop\github\microdh\build-gcc-footprint-msys2-v1\CMakeFiles\4.3.4\CompilerIdC\a-CMakeCCompilerId.su | 41` and `C:\Users\vande\Desktop\github\microdh\build-gcc-footprint-msys2-v1\CMakeFiles\microdh.dir\src\mdh.c.su | 827`
- `Get-Item build-gcc-footprint-msys2-v1\libmicrodh.a | Select-Object FullName,Length` -> length `16422`

## Current fast slice

- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-final-fast -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-final-fast --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-final-fast --output-on-failure` -> `4/4` tests passed in `66.35 sec` total time; oracle label time `51.90 sec`

## Fast rerun after sanitizer fix

- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-fast-gcc-debug-current -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-fast-gcc-debug-current --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-fast-gcc-debug-current --output-on-failure` -> `4/4` tests passed in `65.97 sec` total time; oracle label time `51.50 sec`

## Slow iteration verification

- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-slow-release-gcc -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DMDH_BUILD_TESTS=OFF -DMDH_BUILD_INTERNAL_TESTS=OFF -DMDH_BUILD_DIFFERENTIAL_TESTS=OFF -DMDH_BUILD_SLOW_TESTS=ON -DCMAKE_BUILD_TYPE=Release` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-slow-release-gcc --target mdh_slow_tests --parallel` -> built `mdh_slow_tests.exe`
- `.\build-slow-release-gcc\mdh_slow_tests.exe` -> passed in `794.6 sec`; `[case 1] test_01_one_million_iterations` and `All 1000001 checks passed across 1 cases`

## Fast slice after slow verification

- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-fast-gcc-release-slowstatus -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-fast-gcc-release-slowstatus --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-fast-gcc-release-slowstatus --output-on-failure` -> `4/4` tests passed in `15.09 sec` total time; oracle label time `9.30 sec`

## Current cleanup

- `C:\msys64\ucrt64\bin\cppcheck.exe --inline-suppr --std=c11 --language=c --enable=warning,style,performance,portability --error-exitcode=1 -Iinclude -Itests src tests include\mdh.h` -> exited `0`
- `C:\msys64\ucrt64\bin\clang-tidy.exe -p build-clang-tidy-msys2 C:\Users\vande\Desktop\github\microdh\src\mdh.c --config-file=C:\tmp\clang-tidy-msys2.yaml` -> exited `0` with warnings only; no configuration-read errors
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-sanitize-gcc-msys2 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=OFF -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS=\"-fsanitize=address,undefined -fno-omit-frame-pointer\"` -> failed because `ld.exe` could not find `-lasan` and `-lubsan`
- `C:\msys64\ucrt64\bin\pacman.exe -Ss compiler-rt` -> reported `ucrt64/mingw-w64-ucrt-x86_64-compiler-rt 22.1.7-1` as the matching package
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-slow-gcc-msys2 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DMDH_BUILD_TESTS=OFF -DMDH_BUILD_INTERNAL_TESTS=OFF -DMDH_BUILD_DIFFERENTIAL_TESTS=OFF -DMDH_BUILD_SLOW_TESTS=ON -DCMAKE_BUILD_TYPE=Release` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-slow-gcc-msys2 --config Release --target mdh_slow_tests --parallel` -> built `mdh_slow_tests.exe`
- `C:\Users\vande\Desktop\github\microdh\build-slow-gcc-msys2\mdh_slow_tests.exe` -> timed out after `600000 ms`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-fast-gcc-debug-current -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-fast-gcc-debug-current --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-fast-gcc-debug-current --output-on-failure` -> `4/4` tests passed in `64.71 sec` total time; oracle label time `50.47 sec`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-fast-gcc-release-current -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-fast-gcc-release-current --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-fast-gcc-release-current --output-on-failure` -> `4/4` tests passed in `14.85 sec` total time; oracle label time `9.42 sec`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-fast-clang-debug-current -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/clang.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug` -> configured with Clang 22.1.7
- `C:\msys64\ucrt64\bin\cmake.exe --build build-fast-clang-debug-current --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-fast-clang-debug-current --output-on-failure` -> `4/4` tests passed in `61.37 sec` total time; oracle label time `47.97 sec`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-fast-clang-release-current -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/clang.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON -DMDH_BUILD_DIFFERENTIAL_TESTS=ON -DMDH_STRICT_WARNINGS=ON -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release` -> configured with Clang 22.1.7
- `C:\msys64\ucrt64\bin\cmake.exe --build build-fast-clang-release-current --parallel` -> built `libmicrodh.a`, `mdh_tests.exe`, `mdh_internal_tests.exe`, and `mdh_oracle_tests.exe`
- `C:\msys64\ucrt64\bin\ctest.exe --test-dir build-fast-clang-release-current --output-on-failure` -> `4/4` tests passed in `16.92 sec` total time; oracle label time `10.98 sec`
