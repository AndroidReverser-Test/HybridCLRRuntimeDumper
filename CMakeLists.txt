cmake_minimum_required(VERSION 3.22)
project(HybridCLRRuntimeDumper LANGUAGES CXX)

if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "This project targets Android arm64-v8a. Use the Android NDK toolchain.")
endif()

option(HYBRIDCLR_DUMPER_AUTOSTART "Read the app-private configuration after injection" ON)

add_library(hybridclr_dumper SHARED
    src/config.cpp
    src/entry.cpp
    src/dumper.cpp
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
)
target_link_libraries(hybridclr_dumper PRIVATE log dl)
