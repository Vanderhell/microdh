# Footprint

## Verified in this task

- `cmake -S . -B build-footprint-clang -DMDH_BUILD_TESTS=OFF -DMDH_BUILD_INTERNAL_TESTS=OFF -DMDH_BUILD_DIFFERENTIAL_TESTS=OFF -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -T ClangCL -DCMAKE_C_FLAGS="/clang:-fstack-usage"` -> configured with Clang 19.1.5 with MSVC-like command-line
- `cmake --build build-footprint-clang --config Release --target microdh --parallel` -> built `build-footprint-clang/Release/microdh.lib`
- `Get-ChildItem -Recurse build-footprint-clang -Filter *.su | Select-Object FullName,Length` -> `build-footprint-clang\mdh.su` with length `405`
- `Get-Item build-footprint-clang\Release\microdh.lib | Select-Object FullName,Length` -> length `23228`
- `C:\msys64\ucrt64\bin\cmake.exe -S . -B build-gcc-footprint-msys2-v1 -G Ninja -DCMAKE_C_COMPILER=C:/msys64/ucrt64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/ninja.exe -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DMDH_BUILD_TESTS=OFF -DMDH_BUILD_INTERNAL_TESTS=OFF -DMDH_BUILD_DIFFERENTIAL_TESTS=OFF -DMDH_BUILD_SLOW_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS=\"-fstack-usage\"` -> configured with GNU 16.1.0
- `C:\msys64\ucrt64\bin\cmake.exe --build build-gcc-footprint-msys2-v1 --target microdh --parallel` -> built `libmicrodh.a`
- `Get-ChildItem -Recurse build-gcc-footprint-msys2-v1 -Filter *.su | ForEach-Object { '{0} | {1}' -f $_.FullName, $_.Length }` -> `C:\Users\vande\Desktop\github\microdh\build-gcc-footprint-msys2-v1\CMakeFiles\microdh.dir\src\mdh.c.su | 827`
- `Get-Item build-gcc-footprint-msys2-v1\libmicrodh.a | Select-Object FullName,Length` -> length `16422`

## Not verified

- `-Os` and `-O2` compiler report comparisons
- GCC/Clang text-size comparisons beyond the single measured `microdh.lib` artifact above
- ARM, ESP32, and MCU stack measurements
- Hardware timing measurements

Those measurements remain `NOT VERIFIED` until the relevant toolchains and targets are exercised.
