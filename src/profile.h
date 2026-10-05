#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <string>

namespace hcd::profile {

enum FunctionId : size_t {
    DomainGet, AssemblyImage, ImageName, ClassCount, ImageClass, ClassMethods,
    ThreadCurrent, ThreadAttach, ThreadDetach, UnderlyingImage, FindAotImage, FunctionCount
};

struct FunctionSpec {
    const char* name;
    bool named;
};
// Names and ABI roles only. No sample function addresses or hashes are compiled in.
inline constexpr FunctionSpec kFunctions[FunctionCount] = {
    {"il2cpp_domain_get", true}, {"il2cpp_assembly_get_image", true},
    {"il2cpp_image_get_name", true}, {"il2cpp_image_get_class_count", true},
    {"il2cpp_image_get_class", true}, {"il2cpp_class_get_methods", true},
    {"il2cpp_thread_current", true}, {"il2cpp_thread_attach", true},
    {"il2cpp_thread_detach", true}, {"GetUnderlyingInterpreterImage", false},
    {"FindImageByAssembly", false}
};

struct Function {
    uintptr_t rva = 0;
    size_t fingerprint_length = 0;
    std::string fingerprint_sha256;
};

enum EvidenceId : size_t { RawImageLoad, InitBasic, ImageLoad, EvidenceCount };
inline constexpr const char* kEvidenceNames[EvidenceCount] = {"raw_image_load", "init_basic", "image_load"};
struct LayoutEvidence {
    uintptr_t rva = 0;
    std::string bytes_hex;
};

struct Layout {
    size_t image_raw = 0, image_pdb = 0, raw_data = 0, raw_length = 0, raw_end = 0;
    size_t hot_il2cpp_image = 0, hot_index = 0, aot_target_assembly = 0;
    size_t il2cpp_image_assembly = 0, il2cpp_image_token = 0, assembly_token = 0;
    size_t class_image = 0, class_rank = 0, method_class = 0;
};

struct LayoutSpec {
    const char* name;
    size_t Layout::* member;
    size_t alignment;
};
inline constexpr LayoutSpec kLayouts[] = {
    {"image_raw", &Layout::image_raw, 8}, {"image_pdb", &Layout::image_pdb, 8},
    {"raw_data", &Layout::raw_data, 8}, {"raw_length", &Layout::raw_length, 4},
    {"raw_end", &Layout::raw_end, 8}, {"hot_il2cpp_image", &Layout::hot_il2cpp_image, 8},
    {"hot_index", &Layout::hot_index, 4}, {"aot_target_assembly", &Layout::aot_target_assembly, 8},
    {"il2cpp_image_assembly", &Layout::il2cpp_image_assembly, 8},
    {"il2cpp_image_token", &Layout::il2cpp_image_token, 4}, {"assembly_token", &Layout::assembly_token, 4},
    {"class_image", &Layout::class_image, 8}, {"class_rank", &Layout::class_rank, 1},
    {"method_class", &Layout::method_class, 8}
};

struct RuntimeProfile {
    std::string name;
    std::string analysis_sha256;
    std::array<Function, FunctionCount> functions{};
    std::array<LayoutEvidence, EvidenceCount> evidence{};
    uintptr_t hot_registry_rva = 0;
    uintptr_t aot_vector_rva = 0;
    Layout layout;
};

inline constexpr size_t kHotSlots = 1024;
inline constexpr size_t kMaxAssemblies = 65536;
inline constexpr size_t kMaxClasses = 1048576;

inline bool interpreter_token(uint32_t token) {
    return token != UINT32_MAX && (token & 0xF0000000u) != 0;
}

inline uint32_t image_index(uint32_t token) {
    constexpr uint32_t masks[] = {0x0FFFFFFFu, 0x03FFFFFFu, 0x00FFFFFFu, 0x003FFFFFu};
    return token == UINT32_MAX ? 0 : (token & ~masks[token >> 30]) >> 22;
}

} // namespace hcd::profile
