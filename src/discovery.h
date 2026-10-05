#pragma once

#include "profile.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hcd {

class Memory;
class Module;

struct DiscoveryEvidence {
    std::string name;
    uintptr_t address = 0;
    size_t length = 0;
    std::string sha256;
};

struct RegistryDiscovery {
    uintptr_t hot_registry = 0, aot_vector = 0;
    size_t image_token = 0, image_assembly = 0, aot_target_assembly = 0;
    std::vector<DiscoveryEvidence> evidence;
};

// No target code is invoked. Addresses and evidence are absolute, not RVAs.
// Registry results and getter fields are cleared on failure. Getter/raw evidence
// is appended only on success. Raw layout is preserved on failure; successful
// raw discovery changes ONLY the three raw_* fields.
// Supported ABI: metadata-v2 mask/token encoding, 1024 hot pointer slots,
// three-pointer AOT vector, and Itanium vptr at +0. This is not version inference.
// Registry limits: depth 3, 32 functions, 128 instructions/512-byte function
// window, 4096 visits. Getter/raw prefixes: 32 instructions, 8 B thunks;
// raw discovery requires 16 readable, module-executable vtable slots.
// PAC/PLT/indirect entry thunks and tagged code pointers are not supported.
bool discover_registries(const Memory&, const Module&, uintptr_t pre_jit_class,
                         RegistryDiscovery&, std::string& error);
bool discover_pointer_getter(const Memory&, const Module&, uintptr_t entry,
                            size_t& field, std::vector<DiscoveryEvidence>&, std::string& error);
bool discover_raw_layout(const Memory&, const Module&, uintptr_t raw_object,
                         profile::Layout& layout, std::vector<DiscoveryEvidence>&, std::string& error);

namespace discovery_detail {

// Offline test seam, NOT a Module mutation hook. read must report failed reads;
// contains must enforce readable module ranges and, when requested, executable
// ranges. Only raw_object's vptr read may be outside the module. Neither callback
// may invoke target code. Production adapters use Memory::read/Module::contains.
struct Reader {
    const void* context = nullptr;
    bool (*read)(const void*, uintptr_t, void*, size_t) = nullptr;
    bool (*contains)(const void*, uintptr_t, size_t, bool executable) = nullptr;
};

bool discover_registries(const Reader&, uintptr_t pre_jit_class, RegistryDiscovery&, std::string& error);
bool discover_pointer_getter(const Reader&, uintptr_t entry, size_t& field,
                            std::vector<DiscoveryEvidence>&, std::string& error);
bool discover_raw_layout(const Reader&, uintptr_t raw_object, profile::Layout& layout,
                         std::vector<DiscoveryEvidence>&, std::string& error);

} // namespace discovery_detail
} // namespace hcd
