cmake_minimum_required(VERSION 3.22)
project(HybridCLRRuntimeDumper LANGUAGES CXX)

if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "This project targets Android arm64-v8a. Use the Android NDK toolchain.")
endif()

option(HYBRIDCLR_DUMPER_AUTOSTART "Read the app-private configuration after injection" ON)
option(HYBRIDCLR_DUMPER_BUILD_TESTS "Build native configuration/PE regression checks" OFF)

add_library(hybridclr_dumper SHARED
    src/config.cpp
    src/entry.cpp
    src/dumper.cpp
    src/discovery.cpp
    src/platform.cpp
    src/sha256.cpp
    src/pe.cpp
)
target_compile_features(hybridclr_dumper PRIVATE cxx_std_17)
target_include_directories(hybridclr_dumper PUBLIC include PRIVATE src)
target_compile_definitions(hybridclr_dumper PRIVATE
    HYBRIDCLR_DUMPER_AUTOSTART=$<BOOL:${HYBRIDCLR_DUMPER_AUTOSTART}>
)
target_compile_options(hybridclr_dumper PRIVATE
    -Wall -Wextra -Wpedantic -fvisibility=hidden -fvisibility-inlines-hidden
    -fstack-protector-strong -ffunction-sections -fdata-sections
)
target_link_options(hybridclr_dumper PRIVATE
    -Wl,--no-undefined -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now
    -Wl,-z,max-page-size=16384
    -Wl,--exclude-libs,ALL
)
target_link_libraries(hybridclr_dumper PRIVATE log dl)

if(HYBRIDCLR_DUMPER_BUILD_TESTS)
    add_executable(hybridclr_native_checks
        verification/native_checks.cpp src/config.cpp src/platform.cpp src/sha256.cpp src/pe.cpp
    )
    target_compile_features(hybridclr_native_checks PRIVATE cxx_std_17)
    target_include_directories(hybridclr_native_checks PRIVATE include src)
    target_compile_options(hybridclr_native_checks PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_options(hybridclr_native_checks PRIVATE -Wl,-z,max-page-size=16384)
    target_link_libraries(hybridclr_native_checks PRIVATE log dl)
    add_executable(hybridclr_discovery_checks
        verification/discovery_checks.cpp src/discovery.cpp src/platform.cpp src/sha256.cpp
    )
    target_compile_features(hybridclr_discovery_checks PRIVATE cxx_std_17)
    target_include_directories(hybridclr_discovery_checks PRIVATE include src)
    target_compile_options(hybridclr_discovery_checks PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_options(hybridclr_discovery_checks PRIVATE -Wl,-z,max-page-size=16384)
    target_link_libraries(hybridclr_discovery_checks PRIVATE log dl)
    add_library(hybridclr_raw_fixture SHARED verification/raw_fixture.cpp)
    target_compile_features(hybridclr_raw_fixture PRIVATE cxx_std_17)
    target_compile_options(hybridclr_raw_fixture PRIVATE -Wall -Wextra -Wpedantic -Werror -fvisibility=hidden)
    target_link_options(hybridclr_raw_fixture PRIVATE -Wl,-z,max-page-size=16384 -Wl,--exclude-libs,ALL)
    add_executable(hybridclr_dumper_checks
        verification/dumper_checks.cpp src/discovery.cpp src/platform.cpp src/pe.cpp src/sha256.cpp
    )
    target_compile_features(hybridclr_dumper_checks PRIVATE cxx_std_17)
    target_include_directories(hybridclr_dumper_checks PRIVATE include src)
    target_compile_options(hybridclr_dumper_checks PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_options(hybridclr_dumper_checks PRIVATE -Wl,-z,max-page-size=16384)
    target_link_libraries(hybridclr_dumper_checks PRIVATE hybridclr_raw_fixture log dl)
endif()
