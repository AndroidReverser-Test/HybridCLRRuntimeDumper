#include "hybridclr_dumper.h"
#include "format.h"
#include "internal.h"
#include "profile.h"
#include "discovery.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace hcd {
namespace {

struct Il2CppDomain;
struct Il2CppAssembly;
struct Il2CppImage;
struct Il2CppClass;
struct Il2CppThread;
struct MethodInfo;

struct Binding {
    std::string name, source;
    uintptr_t address = 0, rva = 0;
    size_t length = 0;
    std::string expected_hash, actual_hash;
};

struct Api {
    Il2CppDomain* (*domain_get)() = nullptr;
    const Il2CppImage* (*assembly_image)(const Il2CppAssembly*) = nullptr;
    const char* (*image_name)(const Il2CppImage*) = nullptr;
    size_t (*class_count)(const Il2CppImage*) = nullptr;
    Il2CppClass* (*image_class)(const Il2CppImage*, size_t) = nullptr;
    const MethodInfo* (*class_methods)(Il2CppClass*, void**) = nullptr;
    Il2CppThread* (*thread_current)() = nullptr;
    Il2CppThread* (*thread_attach)(Il2CppDomain*) = nullptr;
    void (*thread_detach)(Il2CppThread*) = nullptr;
    void* (*underlying_image)(const MethodInfo*) = nullptr;
    void* (*find_aot_image)(const Il2CppAssembly*) = nullptr;
    void* (*resolve_icall)(const char*) = nullptr;
};

template<typename T> T pointer(uintptr_t value) { return reinterpret_cast<T>(value); }
template<typename T> uintptr_t address(T ptr) { return reinterpret_cast<uintptr_t>(ptr); }

struct Cancelled {};
void check_cancel(const std::atomic<bool>& flag) { if (flag.load()) throw Cancelled{}; }

struct Attachment {
    Api* api = nullptr;
    Il2CppThread* thread = nullptr;
    bool owned = false;
    ~Attachment() {
        if (owned && thread) api->thread_detach(thread);
    }
};

struct Registries {
    std::array<uintptr_t, profile::kHotSlots> hot{};
    std::array<uintptr_t, 3> aot_bounds{};
    std::vector<uintptr_t> aot;
    bool operator==(const Registries& other) const {
        return hot == other.hot && aot_bounds == other.aot_bounds && aot == other.aot;
    }
};

struct Chunk {
    uint64_t offset = 0, length = 0;
    std::string hash;
};

struct Raw {
    uintptr_t object = 0, data = 0, end = 0;
    uint32_t length = 0;
    bool operator==(const Raw& other) const {
        return object == other.object && data == other.data && end == other.end && length == other.length;
    }
};

struct Blob {
    Raw raw;
    profile::Layout layout;
    std::string status = "NOT_ATTEMPTED", reason, filename;
    uint64_t written = 0;
    bool coverage_complete = false;
    std::string output_hash, live_hash;
    FileInfo format;
    std::vector<Chunk> chunks;
};

struct Candidate {
    size_t id = 0;
    std::string kind, name;
    std::vector<std::string> sources;
    uintptr_t hybrid_image = 0, assembly = 0, il2cpp_image = 0, method = 0;
    uint32_t registry_index = UINT32_MAX;
    bool query_confirmed = false, registered = false, association_verified = false;
    bool native_name_matches_metadata = false;
    std::string association_route, private_query_status = "NOT_REQUESTED";
    profile::Layout layout;
    std::string error, status = "PENDING_INITIALIZATION";
    size_t duplicate_of = 0;
    Blob dll, pdb;
};

struct Report {
    std::string directory, started, error;
    Module module;
    std::vector<Binding> bindings;
    std::vector<DiscoveryEvidence> discovery_evidence;
    bool discovery_evidence_unchanged = false;
    std::vector<Candidate> candidates;
    Registries before;
    bool registry_snapshot_taken = false, snapshot_unchanged = false, all_registered_inputs_exported = false;
    bool complete = false, cancelled = false;
    int result = HYBRIDCLR_DUMP_ERROR;
};

std::string bytes_hex(const std::vector<uint8_t>& bytes) {
    constexpr const char* digits = "0123456789abcdef";
    std::string text;
    for (uint8_t byte : bytes) { text += digits[byte >> 4]; text += digits[byte & 15]; }
    return text;
}

uintptr_t bind(const profile::FunctionSpec& spec, const profile::Function& function, const Memory& memory,
               const Module& module, std::vector<Binding>& bindings) {
    uintptr_t expected = module.at(function.rva);
    uintptr_t resolved = spec.named ? module.symbol(memory, spec.name) : 0;
    Binding record{spec.name, resolved ? "ELF_DYNAMIC_SYMBOL" : "VERIFIED_CONFIG_RVA",
                   resolved ? resolved : expected, function.rva, function.fingerprint_length,
                   function.fingerprint_sha256, ""};
    if (record.address != expected || (record.address & 3) ||
        !module.contains(record.address, record.length, true) || !memory.executable(record.address, record.length)) {
        bindings.push_back(record);
        throw std::runtime_error(std::string("Function address/config mismatch: ") + spec.name);
    }
    std::vector<uint8_t> bytes(record.length);
    if (!memory.read(record.address, bytes.data(), bytes.size())) {
        bindings.push_back(record);
        throw std::runtime_error(std::string("Cannot read function: ") + spec.name);
    }
    record.actual_hash = sha256(bytes.data(), bytes.size());
    bindings.push_back(record);
    if (record.actual_hash != record.expected_hash)
        throw std::runtime_error(std::string("Code fingerprint mismatch: ") + spec.name);
    return record.address;
}

uintptr_t bind_export(const profile::FunctionSpec& spec, const Memory& memory,
                      const Module& module, std::vector<Binding>& bindings) {
    uintptr_t location = module.symbol(memory, spec.name);
    if (!location || (location & 3) || !module.contains(location, 4, true) || !memory.executable(location, 4))
        throw std::runtime_error(std::string("Auto discovery requires a real module export: ") + spec.name);
    uint32_t word = 0;
    if (!memory.value(location, word)) throw std::runtime_error("Unreadable exported API entry");
    bindings.push_back({spec.name, "ELF_DYNAMIC_SYMBOL_ABI", location, location - module.bias,
                        sizeof(word), "", sha256(&word, sizeof(word))});
    return location;
}

Api bind_api(const Config& config, const Memory& memory, const Module& module, std::vector<Binding>& bindings) {
    Api api;
    auto resolve = [&](profile::FunctionId id) {
        return config.automatic_discovery ? bind_export(profile::kFunctions[id], memory, module, bindings) :
            bind(profile::kFunctions[id], config.profile.functions[id], memory, module, bindings);
    };
    api.domain_get = pointer<decltype(api.domain_get)>(resolve(profile::DomainGet));
    api.assembly_image = pointer<decltype(api.assembly_image)>(resolve(profile::AssemblyImage));
    api.image_name = pointer<decltype(api.image_name)>(resolve(profile::ImageName));
    api.thread_current = pointer<decltype(api.thread_current)>(resolve(profile::ThreadCurrent));
    api.thread_attach = pointer<decltype(api.thread_attach)>(resolve(profile::ThreadAttach));
    api.thread_detach = pointer<decltype(api.thread_detach)>(resolve(profile::ThreadDetach));
    if (config.automatic_discovery) {
        api.resolve_icall = pointer<decltype(api.resolve_icall)>(resolve(profile::ResolveIcall));
        return api;
    }
    api.class_count = pointer<decltype(api.class_count)>(resolve(profile::ClassCount));
    api.image_class = pointer<decltype(api.image_class)>(resolve(profile::ImageClass));
    api.class_methods = pointer<decltype(api.class_methods)>(resolve(profile::ClassMethods));
    api.underlying_image = pointer<decltype(api.underlying_image)>(resolve(profile::UnderlyingImage));
    api.find_aot_image = pointer<decltype(api.find_aot_image)>(resolve(profile::FindAotImage));
    for (size_t i = 0; i < profile::EvidenceCount; ++i) {
        const auto& evidence = config.profile.evidence[i];
        size_t length = evidence.bytes_hex.size() / 2;
        std::vector<uint8_t> bytes(length);
        uintptr_t location = module.at(evidence.rva);
        bool read = module.contains(location, length, true) && memory.executable(location, length) &&
                    memory.read(location, bytes.data(), length);
        Binding entry{profile::kEvidenceNames[i], "CONFIG_LAYOUT_CODE_EVIDENCE", location, evidence.rva, length, "", ""};
        if (read) entry.actual_hash = sha256(bytes.data(), bytes.size());
        bindings.push_back(entry);
        if (!read || bytes_hex(bytes) != evidence.bytes_hex)
            throw std::runtime_error(std::string("Layout code fingerprint mismatch: ") + profile::kEvidenceNames[i]);
    }
    return api;
}

void refresh(Memory& memory) {
    std::string error;
    if (!memory.refresh(error)) throw std::runtime_error(error);
}

void append_evidence(Report& report, const std::vector<DiscoveryEvidence>& evidence) {
    for (const auto& entry : evidence) {
        auto found = std::find_if(report.discovery_evidence.begin(), report.discovery_evidence.end(),
            [&](const DiscoveryEvidence& previous) { return previous.address == entry.address && previous.length == entry.length; });
        if (found == report.discovery_evidence.end()) report.discovery_evidence.push_back(entry);
        else if (found->sha256 != entry.sha256) throw std::runtime_error("Semantic discovery evidence changed between objects");
    }
}

bool audit_auto_evidence(const Report& report, const Memory& memory, const std::atomic<bool>& cancelled) {
    check_cancel(cancelled);
    bool unchanged = true;
    for (const auto& evidence : report.discovery_evidence) {
        check_cancel(cancelled);
        std::vector<uint8_t> bytes(evidence.length);
        if (!memory.read(evidence.address, bytes.data(), bytes.size()) || sha256(bytes.data(), bytes.size()) != evidence.sha256)
            unchanged = false;
    }
    for (const auto& binding : report.bindings) {
        check_cancel(cancelled);
        std::vector<uint8_t> bytes(binding.length);
        if (!memory.read(binding.address, bytes.data(), bytes.size()) || sha256(bytes.data(), bytes.size()) != binding.actual_hash)
            unchanged = false;
    }
    check_cancel(cancelled);
    return unchanged;
}

void initialize_auto_profile(Config& config, Api& api, Memory& memory, Report& report,
                             std::chrono::steady_clock::time_point deadline, const std::atomic<bool>& cancelled) {
    uintptr_t entry = 0;
    while (!(entry = address(api.resolve_icall("HybridCLR.RuntimeApi::PreJitClass(System.Type)")))) {
        check_cancel(cancelled);
        if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("HybridCLR PreJitClass icall readiness timeout");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    refresh(memory);
    RegistryDiscovery found;
    std::string error;
    if (!discover_registries(memory, report.module, entry, found, error))
        throw std::runtime_error("Unsupported auto registry discovery: " + error);
    append_evidence(report, found.evidence);
    config.profile.hot_registry_rva = found.hot_registry - report.module.bias;
    config.profile.aot_vector_rva = found.aot_vector - report.module.bias;
    auto& layout = config.profile.layout;
    layout.il2cpp_image_token = found.image_token;
    layout.il2cpp_image_assembly = found.image_assembly;
    layout.aot_target_assembly = found.aot_target_assembly;
    std::vector<DiscoveryEvidence> getters;
    if (!discover_pointer_getter(memory, report.module, address(api.assembly_image), layout.assembly_image, getters, error) ||
        !discover_pointer_getter(memory, report.module, address(api.image_name), layout.il2cpp_image_name, getters, error))
        throw std::runtime_error("Unsupported auto identity getter: " + error);
    append_evidence(report, getters);
    log("Semantic discovery: hot=%s, aot=%s; no private queries or configured RVAs",
        pointer_text(config.profile.hot_registry_rva).c_str(), pointer_text(config.profile.aot_vector_rva).c_str());
}

Registries registry_snapshot(Memory& memory, const Module& module, const Config& config) {
    refresh(memory);
    Registries registries;
    uintptr_t hot = module.at(config.profile.hot_registry_rva), aot = module.at(config.profile.aot_vector_rva);
    if (!module.contains(hot, sizeof(registries.hot)) || !module.contains(aot, sizeof(registries.aot_bounds)) ||
        !memory.read(hot, registries.hot.data(), sizeof(registries.hot)) ||
        !memory.read(aot, registries.aot_bounds.data(), sizeof(registries.aot_bounds)))
        throw std::runtime_error("Cannot read both HybridCLR registries");
    uintptr_t begin = untag(registries.aot_bounds[0]);
    uintptr_t end = untag(registries.aot_bounds[1]), capacity = untag(registries.aot_bounds[2]);
    if (begin == 0 && end == 0 && capacity == 0) return registries;
    if (!begin || end < begin || capacity < end || (end - begin) % 8 || (capacity - begin) % 8 ||
        (end - begin) / 8 > profile::kMaxAssemblies)
        throw std::runtime_error("Invalid AOT vector begin/end/capacity");
    registries.aot.resize((end - begin) / 8);
    if (!memory.read(registries.aot_bounds[0], registries.aot.data(), registries.aot.size() * sizeof(uintptr_t)))
        throw std::runtime_error("Unreadable AOT vector pointer array");
    return registries;
}

std::string image_name(Api& api, const Memory& memory, uintptr_t image) {
    uintptr_t name = address(api.image_name(pointer<const Il2CppImage*>(image)));
    std::string text;
    if (!memory.read_string(name, text)) throw std::runtime_error("Unreadable or unterminated image name");
    return text;
}

bool verify_hot(const Memory& memory, uintptr_t hybrid, uintptr_t image, uint32_t slot,
                uintptr_t assembly, const profile::Layout& layout, bool automatic, std::string& error) {
    uintptr_t associated = 0, owner = 0, assembly_image = 0;
    uint32_t index = 0, token = 0, assembly_token = 0;
    if (!hybrid || !image || !assembly || slot == 0 || slot >= profile::kHotSlots ||
        !memory.value(hybrid + layout.hot_il2cpp_image, associated) ||
        (!automatic && (!memory.value(hybrid + layout.hot_index, index) || index != slot)) ||
        !memory.value(image + layout.il2cpp_image_token, token) ||
        !memory.value(image + layout.il2cpp_image_assembly, owner) ||
        (!automatic && (!memory.value(assembly + layout.assembly_token, assembly_token) || !assembly_token)) ||
        !memory.value(assembly + layout.assembly_image, assembly_image) || !same_pointer(associated, image) ||
        !profile::interpreter_token(token) || profile::image_index(token) != slot ||
        !same_pointer(owner, assembly) || !same_pointer(assembly_image, image)) {
        error = "Hot image/token/registry slot/assembly association mismatch";
        return false;
    }
    return true;
}

bool verify_aot(const Memory& memory, uintptr_t hybrid, uintptr_t assembly, uintptr_t image,
                const profile::Layout& layout, bool automatic, std::string& error) {
    uintptr_t target = 0, associated = 0, owner = 0;
    uint32_t token = UINT32_MAX, assembly_token = 0;
    if (!hybrid || !assembly || !image ||
        !memory.value(hybrid + layout.aot_target_assembly, target) || !same_pointer(target, assembly) ||
        (!automatic && (!memory.value(assembly + layout.assembly_token, assembly_token) || !assembly_token)) ||
        !memory.value(assembly + layout.assembly_image, associated) || !same_pointer(associated, image) ||
        !memory.value(image + layout.il2cpp_image_assembly, owner) || !same_pointer(owner, assembly) ||
        !memory.value(image + layout.il2cpp_image_token, token) || profile::interpreter_token(token)) {
        error = "AOT supplementary image/target assembly association mismatch";
        return false;
    }
    return true;
}

void auto_hot_association(Candidate& candidate, const Memory& memory) {
    size_t matches = 0;
    for (size_t offset = sizeof(uintptr_t); offset < profile::kImageAssociationBytes; offset += sizeof(uintptr_t)) {
        uintptr_t image = 0, assembly = 0;
        uint32_t token = 0;
        if (!memory.value(candidate.hybrid_image + offset, image) || !image ||
            !memory.value(image + candidate.layout.il2cpp_image_token, token) ||
            !profile::interpreter_token(token) || profile::image_index(token) != candidate.registry_index ||
            !memory.value(image + candidate.layout.il2cpp_image_assembly, assembly)) continue;
        auto layout = candidate.layout;
        layout.hot_il2cpp_image = offset;
        std::string error;
        if (!verify_hot(memory, candidate.hybrid_image, image, candidate.registry_index, assembly, layout, true, error)) continue;
        ++matches;
        candidate.il2cpp_image = image;
        candidate.assembly = assembly;
        candidate.layout.hot_il2cpp_image = offset;
    }
    if (matches != 1) throw std::runtime_error(matches ? "Ambiguous hot native image back-pointers" :
        "No supported hot image/assembly association in bounded object prefix");
}

uintptr_t representative_method(Api& api, Memory& memory, uintptr_t image,
                                const profile::Layout& layout, const std::atomic<bool>& cancelled) {
    size_t count = api.class_count(pointer<const Il2CppImage*>(image));
    if (count > profile::kMaxClasses) throw std::runtime_error("Implausible image class count");
    for (size_t i = 0; i < count; ++i) {
        check_cancel(cancelled);
        Il2CppClass* klass = api.image_class(pointer<const Il2CppImage*>(image), i);
        if (!klass) continue;
        refresh(memory);
        uintptr_t class_image = 0;
        uint8_t rank = 0;
        if (!memory.value(address(klass) + layout.class_image, class_image) ||
            !memory.value(address(klass) + layout.class_rank, rank))
            throw std::runtime_error("Unreadable real class descriptor");
        if (!same_pointer(class_image, image) || rank != 0) continue;
        void* iterator = nullptr;
        const MethodInfo* method = api.class_methods(klass, &iterator);
        if (!method) continue;
        refresh(memory);
        uintptr_t owner = 0;
        if (!memory.value(address(method) + layout.method_class, owner) || !same_pointer(owner, address(klass)))
            throw std::runtime_error("Representative MethodInfo does not belong to the enumerated class");
        return address(method);
    }
    return 0;
}

Candidate& add_candidate(Report& report, std::map<uintptr_t, size_t>& indices, uintptr_t hybrid,
                         const std::string& kind, const std::string& source) {
    uintptr_t key = untag(hybrid);
    auto found = indices.find(key);
    if (found == indices.end()) {
        size_t index = report.candidates.size();
        Candidate candidate;
        candidate.id = index + 1;
        candidate.kind = kind;
        candidate.hybrid_image = hybrid;
        report.candidates.push_back(std::move(candidate));
        found = indices.emplace(key, index).first;
    }
    Candidate& candidate = report.candidates[found->second];
    if (candidate.kind != kind) candidate.error = "Same HybridCLR object appears in both registry kinds";
    if (std::find(candidate.sources.begin(), candidate.sources.end(), source) == candidate.sources.end())
        candidate.sources.push_back(source);
    return candidate;
}

void discover(Report& report, Api& api, Memory& memory, const Config& config,
              const std::atomic<bool>& cancelled) {
    std::map<uintptr_t, size_t> indices;
    // Record the complete registry union before any per-image runtime query.
    for (size_t slot = 0; slot < report.before.hot.size(); ++slot) {
        uintptr_t hybrid = report.before.hot[slot];
        if (!hybrid) continue;
        Candidate& candidate = add_candidate(report, indices, hybrid, "HOT_UPDATE",
            "HOT_REGISTRY_SLOT_" + std::to_string(slot));
        if (candidate.registered) candidate.error = "Same hot object is registered in multiple slots";
        candidate.registered = true;
        candidate.registry_index = static_cast<uint32_t>(slot);
        candidate.name = "registry_hot_" + std::to_string(slot);
    }
    for (size_t element = 0; element < report.before.aot.size(); ++element) {
        uintptr_t hybrid = report.before.aot[element];
        std::string source = "AOT_REGISTRY_ELEMENT_" + std::to_string(element);
        if (!hybrid) {
            Candidate empty;
            empty.id = report.candidates.size() + 1;
            empty.kind = "AOT_SUPPLEMENT";
            empty.registered = true;
            empty.sources.push_back(source);
            empty.error = "Null object inside the valid AOT vector range";
            report.candidates.push_back(std::move(empty));
            continue;
        }
        Candidate& candidate = add_candidate(report, indices, hybrid, "AOT_SUPPLEMENT", source);
        if (candidate.registered) candidate.error = "Same object is registered more than once";
        candidate.registered = true;
        candidate.name = "registry_aot_" + std::to_string(candidate.id);
    }

    for (auto& candidate : report.candidates) {
        check_cancel(cancelled);
        if (!candidate.error.empty()) continue;
        try {
            refresh(memory);
            candidate.layout = config.profile.layout;
            const auto& layout = candidate.layout;
            bool hot = candidate.kind == "HOT_UPDATE";
            if (hot) {
                if (config.automatic_discovery) auto_hot_association(candidate, memory);
                else if (!memory.value(candidate.hybrid_image + layout.hot_il2cpp_image, candidate.il2cpp_image) ||
                    !candidate.il2cpp_image ||
                    !memory.value(candidate.il2cpp_image + layout.il2cpp_image_assembly, candidate.assembly))
                    throw std::runtime_error("Unreadable registered hot image/assembly association");
                candidate.association_verified = verify_hot(memory, candidate.hybrid_image, candidate.il2cpp_image,
                    candidate.registry_index, candidate.assembly, layout, config.automatic_discovery, candidate.error);
            } else {
                if (!memory.value(candidate.hybrid_image + layout.aot_target_assembly, candidate.assembly) ||
                    !candidate.assembly || !memory.value(candidate.assembly + layout.assembly_image, candidate.il2cpp_image))
                    throw std::runtime_error("Unreadable registered AOT target assembly/image");
                candidate.association_verified = verify_aot(memory, candidate.hybrid_image, candidate.assembly,
                    candidate.il2cpp_image, layout, config.automatic_discovery, candidate.error);
            }
            if (!candidate.association_verified) continue;
            if (config.automatic_discovery) {
                uintptr_t name = 0;
                std::string text;
                if (!memory.value(candidate.il2cpp_image + layout.il2cpp_image_name, name) ||
                    !memory.read_string(name, text) || text.empty())
                    throw std::runtime_error("Unreadable native name before public identity getter calls");
            }
            uintptr_t image = address(api.assembly_image(pointer<const Il2CppAssembly*>(candidate.assembly)));
            if (!same_pointer(image, candidate.il2cpp_image))
                throw std::runtime_error("assembly_get_image disagrees with the registry association");
            candidate.name = image_name(api, memory, image);
            if (config.automatic_discovery) {
                candidate.association_route = "SEMANTIC_REGISTRY_PUBLIC_API";
                candidate.sources.push_back("PUBLIC_API_REGISTRY_ASSOCIATION");
            } else if (hot) {
                candidate.method = representative_method(api, memory, image, layout, cancelled);
                if (candidate.method) {
                    uintptr_t underlying = address(api.underlying_image(pointer<const MethodInfo*>(candidate.method)));
                    if (!same_pointer(underlying, candidate.hybrid_image))
                        throw std::runtime_error("Underlying-image query disagrees with the registered hot image");
                    candidate.sources.push_back("GET_UNDERLYING_IMAGE_BY_METHOD");
                    candidate.association_route = "PROFILE_PRIVATE_QUERY";
                    candidate.private_query_status = "MATCH";
                } else {
                    candidate.sources.push_back("TOKEN_REGISTRY_FALLBACK_NO_METHOD");
                    candidate.association_route = "PROFILE_TOKEN_REGISTRY_NO_METHOD";
                    candidate.private_query_status = "NOT_RUN_NO_METHOD";
                }
            } else {
                uintptr_t supplementary = address(api.find_aot_image(pointer<const Il2CppAssembly*>(candidate.assembly)));
                if (!same_pointer(supplementary, candidate.hybrid_image))
                    throw std::runtime_error("FindImageByAssembly disagrees with the registered AOT image");
                candidate.sources.push_back("FIND_AOT_BY_ASSEMBLY");
                candidate.association_route = "PROFILE_PRIVATE_QUERY";
                candidate.private_query_status = "MATCH";
            }
            candidate.query_confirmed = true;
        } catch (const Cancelled&) { throw; }
          catch (const std::exception& error) { candidate.error = error.what(); }
    }
}

bool raw_descriptor(const Memory& memory, uintptr_t object, uint64_t limit, const profile::Layout& layout,
                    Raw& raw, std::string& error) {
    raw.object = object;
    if (!object || !memory.value(object + layout.raw_data, raw.data) ||
        !memory.value(object + layout.raw_length, raw.length) ||
        !memory.value(object + layout.raw_end, raw.end)) {
        error = "Null or unreadable RawImageBase prefix";
        return false;
    }
    uintptr_t data = untag(raw.data), end = untag(raw.end);
    if (!data || !raw.length || raw.length > limit || end < data || end - data != raw.length ||
        !memory.readable(raw.data, raw.length)) {
        error = "Invalid P/N/E, file-size limit exceeded, or incomplete readable raw range";
        return false;
    }
    return true;
}

bool auto_raw_field(Candidate& candidate, bool pdb, Report& report,
                    Memory& memory, uintptr_t& raw_object, profile::Layout& selected_layout, std::string& error) {
    size_t matches = 0;
    std::vector<DiscoveryEvidence> selected_evidence;
    for (size_t offset = sizeof(uintptr_t); offset < profile::kRawOwnerBytes; offset += sizeof(uintptr_t)) {
        uintptr_t object = 0;
        if (!memory.value(candidate.hybrid_image + offset, object) || !object) continue;
        auto layout = candidate.layout;
        std::vector<DiscoveryEvidence> evidence;
        std::string reason;
        if (!discover_raw_layout(memory, report.module, object, layout, evidence, reason)) {
            if (reason == "Ambiguous raw loader methods" || reason == "Overlapping raw loader fields" ||
                reason == "Unsupported or incomplete raw loader store prefix") {
                error = "Unsupported raw-like owner: " + reason;
                return false;
            }
            continue;
        }
        Raw raw;
        // Capture policy must not filter an otherwise real owner into false uniqueness.
        if (!raw_descriptor(memory, object, UINT32_MAX, layout, raw, reason)) {
            error = "Invalid discovered raw descriptor: " + reason;
            return false;
        }
        uint32_t magic = 0;
        if (!memory.value(raw.data, magic)) { error = "Discovered raw header became unreadable"; return false; }
        if (magic != 0x424a5342u && (magic & 0xffffu) != 0x5a4du) {
            error = "Unknown format in a discovered raw owner; cannot certify unique DLL/PDB ownership";
            return false;
        }
        if (pdb) {
            if (magic != 0x424a5342u) continue;
            layout.image_pdb = offset;
        } else {
            uint32_t pe_offset = 0, signature = 0;
            if (magic == 0x424a5342u) continue;
            if (raw.length < 64 ||
                !memory.value(raw.data + 0x3c, pe_offset) || pe_offset > raw.length - 4 ||
                !memory.value(raw.data + pe_offset, signature) || signature != 0x00004550u) {
                error = "Invalid PE header in a discovered DLL raw owner";
                return false;
            }
            layout.image_raw = offset;
        }
        ++matches;
        raw_object = object;
        selected_layout = layout;
        selected_evidence = std::move(evidence);
    }
    if (matches != 1) {
        error = matches ? "Ambiguous retained raw owners in bounded Image prefix" :
            "No positively identified raw owner in bounded Image prefix; absence is not certified";
        return false;
    }
    append_evidence(report, selected_evidence);
    candidate.sources.push_back(pdb ? "SEMANTIC_PDB_LOADER_AND_RAW_OWNER" : "SEMANTIC_DLL_LOADER_AND_RAW_OWNER");
    return true;
}

std::string safe_name(const std::string& name) {
    std::string result;
    for (unsigned char c : name) {
        if (result.size() == 96) break;
        bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        result += allowed ? static_cast<char>(c) : '_';
    }
    return result.empty() ? "unnamed" : result;
}

struct FileDescriptor {
    int fd = -1;
    ~FileDescriptor() { if (fd >= 0) ::close(fd); }
};

void dump_blob(Blob& blob, uintptr_t raw_object, uintptr_t owner_slot, bool pdb,
               const std::string& basename, const profile::Layout& layout, const Config& config, Report& report, Memory& memory,
               const std::atomic<bool>& cancelled) {
    blob.status = "PARTIAL";
    blob.layout = layout;
    refresh(memory);
    if (!raw_descriptor(memory, raw_object, config.max_file_size, layout, blob.raw, blob.reason)) return;
    blob.filename = basename + (pdb ? ".pdb.partial" : ".dll.partial");
    std::string path = report.directory + '/' + blob.filename;
    FileDescriptor output{::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
    if (output.fd < 0) { blob.reason = "Cannot create output: " + std::string(std::strerror(errno)); return; }
    std::vector<uint8_t> buffer(config.chunk_size);
    Sha256 output_hash;
    for (uint64_t offset = 0; offset < blob.raw.length;) {
        if (cancelled.load()) { blob.reason = "Cancelled at a copy block boundary"; break; }
        size_t size = static_cast<size_t>(std::min<uint64_t>(buffer.size(), blob.raw.length - offset));
        if (!memory.copy_payload(blob.raw.data + offset, buffer.data(), size)) {
            blob.reason = "Raw block is not fully readable";
            break;
        }
        size_t written = 0;
        bool ok = write_all(output.fd, buffer.data(), size, written);
        if (written) {
            blob.chunks.push_back({offset, written, sha256(buffer.data(), written)});
            output_hash.update(buffer.data(), written);
            blob.written += written;
            offset += written;
        }
        if (!ok) { blob.reason = "Output write failed: " + std::string(std::strerror(errno)); break; }
    }
    blob.output_hash = output_hash.finish();
    if (blob.written != blob.raw.length) return;
    if (::fsync(output.fd) != 0) { blob.reason = "fsync failed: " + std::string(std::strerror(errno)); return; }

    // A second live pass detects changes; only the caller's gate guarantees lifetime.
    Sha256 live_hash;
    for (uint64_t offset = 0; offset < blob.raw.length;) {
        if (cancelled.load()) { blob.reason = "Cancelled during the second raw hash pass"; return; }
        size_t size = static_cast<size_t>(std::min<uint64_t>(buffer.size(), blob.raw.length - offset));
        if (!memory.copy_payload(blob.raw.data + offset, buffer.data(), size)) {
            blob.reason = "Raw block became unreadable during the second hash pass";
            return;
        }
        live_hash.update(buffer.data(), size);
        offset += size;
    }
    blob.live_hash = live_hash.finish();
    Raw after;
    uintptr_t retained_object = 0;
    if (!memory.value(owner_slot, retained_object) || !same_pointer(retained_object, raw_object) ||
        !raw_descriptor(memory, raw_object, config.max_file_size, layout, after, blob.reason) || !(blob.raw == after)) {
        blob.reason = "Raw descriptor or owning Image field changed while copying";
        return;
    }
    if (blob.live_hash != blob.output_hash) { blob.reason = "Live raw and output SHA-256 differ"; return; }
    void* mapped = ::mmap(nullptr, blob.raw.length, PROT_READ, MAP_PRIVATE, output.fd, 0);
    if (mapped == MAP_FAILED) { blob.reason = "Cannot map output for independent format inspection"; return; }
    try { blob.format = inspect_file(static_cast<const uint8_t*>(mapped), blob.raw.length, pdb); }
    catch (...) { ::munmap(mapped, blob.raw.length); throw; }
    ::munmap(mapped, blob.raw.length);

    std::string extension;
    if (!blob.format.valid) extension = pdb ? ".pdb.invalid.bin" : ".dll.invalid.bin";
    else extension = pdb ? ".pdb" : ".dll";
    std::string final_name = basename + extension;
    if (::rename(path.c_str(), (report.directory + '/' + final_name).c_str()) != 0) {
        blob.reason = "Cannot publish the complete file: " + std::string(std::strerror(errno));
        return;
    }
    blob.filename = final_name;
    blob.coverage_complete = true;
    blob.status = blob.format.valid ? "COMPLETE" : "INVALID_FORMAT";
    blob.reason = blob.format.reason;
}

void capture(Report& report, const Config& config, Memory& memory, const std::atomic<bool>& cancelled) {
    std::map<std::string, size_t> identities;
    for (auto& candidate : report.candidates) {
        check_cancel(cancelled);
        if (!candidate.error.empty() || !candidate.association_verified || !candidate.query_confirmed) {
            candidate.status = "PENDING_INITIALIZATION";
            candidate.dll.status = "PENDING_INITIALIZATION";
            candidate.dll.reason = candidate.error.empty() ? "Image association/query is not verified" : candidate.error;
            continue;
        }
        auto& layout = candidate.layout;
        uintptr_t raw = 0;
        bool retained = config.automatic_discovery ?
            auto_raw_field(candidate, false, report, memory, raw, layout, candidate.error) :
            memory.value(candidate.hybrid_image + layout.image_raw, raw) && raw;
        if (!retained) {
            candidate.status = "PENDING_INITIALIZATION";
            candidate.dll.status = "PENDING_INITIALIZATION";
            candidate.dll.reason = candidate.error.empty() ? "Registered image has no readable retained RawImageBase" : candidate.error;
            continue;
        }
        std::string basename = candidate.kind == "HOT_UPDATE" ? "hot_" : "aot_";
        basename += std::to_string(candidate.id) + '_' + safe_name(candidate.name);
        if (basename.size() >= 4 && basename.substr(basename.size() - 4) == ".dll") basename.resize(basename.size() - 4);
        dump_blob(candidate.dll, raw, candidate.hybrid_image + layout.image_raw, false,
                  basename, layout, config, report, memory, cancelled);
        if (candidate.dll.status == "COMPLETE") {
            std::string native_name = candidate.name;
            if (native_name.size() >= 4) {
                std::string suffix = native_name.substr(native_name.size() - 4);
                for (char& c : suffix) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
                if (suffix == ".dll") native_name.resize(native_name.size() - 4);
            }
            candidate.native_name_matches_metadata = native_name == candidate.dll.format.assembly_name;
            if (!candidate.native_name_matches_metadata) {
                candidate.error = "Native image name disagrees with retained DLL Assembly identity";
                candidate.status = "PARTIAL";
            } else {
                candidate.status = candidate.kind == "HOT_UPDATE" ? "HOT_UPDATE_COMPLETE" : "AOT_SUPPLEMENT_COMPLETE";
            }
            std::string identity = candidate.dll.format.mvid + ':' + candidate.dll.output_hash;
            auto duplicate = identities.emplace(identity, candidate.id);
            if (!duplicate.second) candidate.duplicate_of = duplicate.first->second;
        } else candidate.status = candidate.dll.status;

        log("Capture %zu: %s, %s, %llu/%u bytes", candidate.id, candidate.kind.c_str(),
            candidate.status.c_str(), static_cast<unsigned long long>(candidate.dll.written), candidate.dll.raw.length);
        if (!config.dump_pdb) { candidate.pdb.status = "DISABLED"; continue; }
        check_cancel(cancelled);
        uintptr_t pdb = 0;
        auto pdb_layout = layout;
        if (config.automatic_discovery) {
            if (!auto_raw_field(candidate, true, report, memory, pdb, pdb_layout, candidate.pdb.reason)) {
                candidate.pdb.status = "NOT_DISCOVERED";
            } else dump_blob(candidate.pdb, pdb, candidate.hybrid_image + pdb_layout.image_pdb, true,
                            basename, pdb_layout, config, report, memory, cancelled);
        } else if (!memory.value(candidate.hybrid_image + layout.image_pdb, pdb)) {
            candidate.pdb.status = "PARTIAL";
            candidate.pdb.reason = "Unreadable Image::_pdbImage field";
        } else if (!pdb) candidate.pdb.status = "NOT_PRESENT";
        else dump_blob(candidate.pdb, pdb, candidate.hybrid_image + layout.image_pdb, true,
                       basename, layout, config, report, memory, cancelled);
    }
}

void emit_blob(std::ostream& out, const Blob& blob) {
    out << "{\"status\":" << json_string(blob.status) << ",\"reason\":" << json_string(blob.reason)
        << ",\"raw_object\":" << json_string(pointer_text(blob.raw.object))
        << ",\"data_pointer_original\":" << json_string(pointer_text(blob.raw.data))
        << ",\"data_pointer_untagged\":" << json_string(pointer_text(untag(blob.raw.data)))
        << ",\"end_pointer_original\":" << json_string(pointer_text(blob.raw.end))
        << ",\"declared_length\":" << blob.raw.length << ",\"written_length\":" << blob.written
        << ",\"coverage_complete\":" << (blob.coverage_complete ? "true" : "false")
        << ",\"filename\":" << json_string(blob.filename)
        << ",\"output_sha256\":" << json_string(blob.output_hash)
        << ",\"second_live_pass_sha256\":" << json_string(blob.live_hash)
        << ",\"format_valid\":" << (blob.format.valid ? "true" : "false")
        << ",\"assembly_name_from_metadata\":" << json_string(blob.format.assembly_name)
        << ",\"mvid\":" << json_string(blob.format.mvid)
        << ",\"raw_layout\":{\"data\":" << blob.layout.raw_data << ",\"length\":" << blob.layout.raw_length
        << ",\"end\":" << blob.layout.raw_end << "},\"chunks\":[";
    for (size_t i = 0; i < blob.chunks.size(); ++i) {
        if (i) out << ',';
        const auto& chunk = blob.chunks[i];
        out << "{\"offset\":" << chunk.offset << ",\"length\":" << chunk.length
            << ",\"sha256\":" << json_string(chunk.hash) << '}';
    }
    out << "]}";
}

bool write_manifest(const Report& report, const Config& config, std::string& error) {
    std::ostringstream out;
    size_t hot_count = 0, complete_files = 0;
    std::set<uintptr_t> associated_assemblies;
    for (uintptr_t image : report.before.hot) if (image) ++hot_count;
    for (const auto& entry : report.candidates) {
        if (entry.dll.status == "COMPLETE") ++complete_files;
        if (entry.association_verified) associated_assemblies.insert(untag(entry.assembly));
    }
    out << "{\n\"schema_version\":3,\n\"profile\":" << json_string(config.profile.name)
        << ",\n\"discovery_mode\":" << json_string(config.automatic_discovery ? "auto" : "profile")
        << ",\n\"supported_registry_abi\":\"ARM64_METADATA_V2_1024_HOT_THREE_POINTER_AOT_VECTOR\""
        << ",\n\"payload_copy\":\"FAILURE_REPORTING_KERNEL_READ\""
        << ",\n\"configuration_path\":" << json_string(config.config_path)
        << ",\n\"configuration_sha256\":" << json_string(config.config_sha256)
        << ",\n\"analysis_idb_sha256\":" << json_string(config.profile.analysis_sha256)
        << ",\n\"analysis_hash_is_not_runtime_elf_hash\":true,\n\"pid\":" << ::getpid()
        << ",\n\"worker_tid\":" << ::syscall(SYS_gettid) << ",\n\"started_unix_ms\":" << json_string(report.started)
        << ",\n\"module_path\":" << json_string(report.module.path)
        << ",\n\"module_load_bias\":" << json_string(pointer_text(report.module.bias))
        << ",\n\"runtime_elf_build_id\":" << json_string(report.module.build_id)
        << ",\n\"scope\":\"Currently registered hot-update and supplementary AOT raw inputs; not original ordinary AOT DLLs\""
        << ",\n\"discovery_source\":\"HYBRIDCLR_REGISTRY_UNION\""
        << ",\n\"all_process_assemblies_enumerated\":false"
        << ",\n\"ordinary_aot_without_raw_enumerated\":false"
        << ",\n\"resolved_registry_rvas\":{\"hot\":" << json_string(pointer_text(config.profile.hot_registry_rva))
        << ",\"aot_vector\":" << json_string(pointer_text(config.profile.aot_vector_rva)) << '}'
        << ",\n\"resolved_identity_layout\":{\"image_token\":" << config.profile.layout.il2cpp_image_token
        << ",\"image_assembly\":" << config.profile.layout.il2cpp_image_assembly
        << ",\"assembly_image\":" << config.profile.layout.assembly_image
        << ",\"image_name\":" << config.profile.layout.il2cpp_image_name
        << ",\"aot_target_assembly\":" << config.profile.layout.aot_target_assembly << '}'
        << ",\n\"semantic_evidence_unchanged\":" << (report.discovery_evidence_unchanged ? "true" : "false")
        << ",\n\"stable_window_confirmed_by_caller\":" << (config.stable_window_confirmed ? "true" : "false")
        << ",\n\"experimental_ungated_capture\":" << (!config.stable_window_confirmed ? "true" : "false")
        << ",\n\"unchanged_reads_are_not_a_lifetime_gate\":true"
        << ",\n\"validation_scope\":[\"PE/CLI headers\",\"metadata streams and table bounds\",\"Module MVID and Assembly name\"]"
        << ",\n\"all_IL_and_EH_verified\":false,\n\"registry_snapshot_taken\":"
        << (report.registry_snapshot_taken ? "true" : "false")
        << ",\n\"registry_snapshots_unchanged\":" << (report.snapshot_unchanged ? "true" : "false")
        << ",\n\"all_registered_inputs_exported\":" << (report.all_registered_inputs_exported ? "true" : "false")
        << ",\n\"complete_within_declared_scope\":" << (report.complete ? "true" : "false")
        << ",\n\"result_code\":" << report.result << ",\n\"cancelled\":" << (report.cancelled ? "true" : "false")
        << ",\n\"error\":" << json_string(report.error)
        << ",\n\"counts\":{\"associated_native_assemblies\":" << associated_assemblies.size()
        << ",\"hot_registry_objects\":" << hot_count << ",\"aot_registry_elements\":" << report.before.aot.size()
        << ",\"union_candidates\":" << report.candidates.size() << ",\"raw_files_complete\":" << complete_files
        << "},\n\"function_bindings\":[";
    for (size_t i = 0; i < report.bindings.size(); ++i) {
        if (i) out << ',';
        const auto& binding = report.bindings[i];
        out << "\n{\"name\":" << json_string(binding.name) << ",\"source\":" << json_string(binding.source)
            << ",\"address\":" << json_string(pointer_text(binding.address))
            << ",\"rva\":" << json_string(pointer_text(binding.rva)) << ",\"fingerprint_length\":" << binding.length
            << ",\"expected_sha256\":" << json_string(binding.expected_hash)
            << ",\"actual_sha256\":" << json_string(binding.actual_hash) << '}';
    }
    out << "\n],\n\"semantic_discovery_evidence\":[";
    for (size_t i = 0; i < report.discovery_evidence.size(); ++i) {
        if (i) out << ',';
        const auto& evidence = report.discovery_evidence[i];
        out << "\n{\"name\":" << json_string(evidence.name) << ",\"address\":" << json_string(pointer_text(evidence.address))
            << ",\"length\":" << evidence.length << ",\"sha256\":" << json_string(evidence.sha256) << '}';
    }
    out << "\n],\n\"captures\":[";
    for (size_t i = 0; i < report.candidates.size(); ++i) {
        if (i) out << ',';
        const auto& entry = report.candidates[i];
        out << "\n{\"capture_id\":" << entry.id << ",\"kind\":" << json_string(entry.kind)
            << ",\"name\":" << json_string(entry.name) << ",\"status\":" << json_string(entry.status)
            << ",\"reason\":" << json_string(entry.error)
            << ",\"hybridclr_image\":" << json_string(pointer_text(entry.hybrid_image))
            << ",\"native_assembly\":" << json_string(pointer_text(entry.assembly))
            << ",\"il2cpp_image\":" << json_string(pointer_text(entry.il2cpp_image))
            << ",\"representative_method\":" << json_string(pointer_text(entry.method))
            << ",\"registry_index\":";
        if (entry.registry_index == UINT32_MAX) out << "null"; else out << entry.registry_index;
        out << ",\"query_confirmed\":" << (entry.query_confirmed ? "true" : "false")
            << ",\"association_route\":" << json_string(entry.association_route)
            << ",\"private_query_status\":" << json_string(entry.private_query_status)
            << ",\"native_name_matches_metadata\":" << (entry.native_name_matches_metadata ? "true" : "false")
            << ",\"resolved_owner_layout\":{\"hot_il2cpp_image\":" << entry.layout.hot_il2cpp_image
            << ",\"image_raw\":" << entry.layout.image_raw << ",\"image_pdb\":" << entry.pdb.layout.image_pdb << '}'
            << ",\"registered\":" << (entry.registered ? "true" : "false")
            << ",\"association_verified\":" << (entry.association_verified ? "true" : "false")
            << ",\"duplicate_of_capture_id\":" << entry.duplicate_of << ",\"sources\":[";
        for (size_t j = 0; j < entry.sources.size(); ++j) {
            if (j) out << ',';
            out << json_string(entry.sources[j]);
        }
        out << "],\"dll\":";
        emit_blob(out, entry.dll);
        out << ",\"pdb\":";
        emit_blob(out, entry.pdb);
        out << '}';
    }
    out << "\n]\n}\n";
    std::string text = out.str();
    std::string temporary = report.directory + "/manifest.json.partial";
    FileDescriptor fd{::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
    size_t written = 0;
    if (fd.fd < 0 || !write_all(fd.fd, text.data(), text.size(), written) || ::fsync(fd.fd) != 0 ||
        ::rename(temporary.c_str(), (report.directory + "/manifest.json").c_str()) != 0) {
        error = "Cannot publish manifest: " + std::string(std::strerror(errno));
        return false;
    }
    FileDescriptor directory{::open(report.directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (directory.fd < 0 || ::fsync(directory.fd) != 0) {
        error = "Cannot sync output directory: " + std::string(std::strerror(errno));
        return false;
    }
    return true;
}

} // namespace

int dump_runtime(const Config& requested_config, const std::atomic<bool>& cancelled) {
    Config config = requested_config;
    Report report;
    try {
        std::string error;
        if (!make_directories(config.output_directory, error)) throw std::runtime_error(error);
        static std::atomic<uint64_t> sequence{0};
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        report.started = std::to_string(milliseconds);
        report.directory = config.output_directory + '/' + report.started + '-' +
                           std::to_string(::getpid()) + '-' + std::to_string(sequence.fetch_add(1));
        if (::mkdir(report.directory.c_str(), 0700) != 0) {
            report.directory.clear();
            throw std::runtime_error("Cannot create a new capture session directory");
        }
        log("Starting active runtime queries; output: %s", report.directory.c_str());
        Memory memory;
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(config.initialization_timeout_seconds);
        while (!report.module.find(config.module_name, error)) {
            check_cancel(cancelled);
            if (error.find("Ambiguous") == 0 || std::chrono::steady_clock::now() >= deadline)
                throw std::runtime_error(error);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        refresh(memory);
        if (!report.module.initialize_symbols(memory, error)) throw std::runtime_error(error);
        Api api = bind_api(config, memory, report.module, report.bindings);
        Il2CppDomain* domain = nullptr;
        while (!(domain = api.domain_get())) {
            check_cancel(cancelled);
            if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("IL2CPP domain readiness timeout");
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        check_cancel(cancelled);
        Attachment attached{&api, api.thread_current(), false};
        if (!attached.thread) {
            attached.thread = api.thread_attach(domain);
            attached.owned = attached.thread != nullptr;
            if (!attached.thread) throw std::runtime_error("il2cpp_thread_attach returned null");
        }
        if (config.automatic_discovery) initialize_auto_profile(config, api, memory, report, deadline, cancelled);
        report.before = registry_snapshot(memory, report.module, config);
        report.registry_snapshot_taken = true;
        discover(report, api, memory, config, cancelled);
        capture(report, config, memory, cancelled);
        check_cancel(cancelled);
        Registries after = registry_snapshot(memory, report.module, config);
        report.snapshot_unchanged = report.before == after;
        if (!report.snapshot_unchanged) report.error = "Registry snapshot changed; not a coherent stable capture";
        report.all_registered_inputs_exported = report.snapshot_unchanged;
        if (report.candidates.empty()) {
            report.error = "No registered retained inputs discovered; confirm the loading stage";
            report.all_registered_inputs_exported = false;
        }
        for (auto& candidate : report.candidates) {
            std::string mismatch;
            bool associated = candidate.kind == "HOT_UPDATE" ?
                verify_hot(memory, candidate.hybrid_image, candidate.il2cpp_image, candidate.registry_index,
                           candidate.assembly, candidate.layout, config.automatic_discovery, mismatch) :
                verify_aot(memory, candidate.hybrid_image, candidate.assembly, candidate.il2cpp_image,
                           candidate.layout, config.automatic_discovery, mismatch);
            if (!associated) {
                if (candidate.error.empty()) candidate.error = mismatch;
                if (candidate.query_confirmed) candidate.status = "PARTIAL";
            }
            bool dll_ok = candidate.status == "HOT_UPDATE_COMPLETE" || candidate.status == "AOT_SUPPLEMENT_COMPLETE";
            bool pdb_ok = !config.dump_pdb || candidate.pdb.status == "NOT_PRESENT" || candidate.pdb.status == "COMPLETE";
            if (!dll_ok || !pdb_ok || !candidate.error.empty()) report.all_registered_inputs_exported = false;
        }
        if (config.automatic_discovery) {
            report.discovery_evidence_unchanged = audit_auto_evidence(report, memory, cancelled);
            if (!report.discovery_evidence_unchanged) {
                report.error = "Semantic discovery code/GOT/vtable evidence changed during capture";
                report.all_registered_inputs_exported = false;
            }
        }
        report.complete = config.stable_window_confirmed && report.all_registered_inputs_exported;
        report.result = report.complete ? HYBRIDCLR_DUMP_OK : HYBRIDCLR_DUMP_INCOMPLETE;
    } catch (const Cancelled&) {
        report.cancelled = true;
        report.error = "Cooperative cancellation requested";
        report.result = HYBRIDCLR_DUMP_CANCELLED;
    } catch (const std::exception& error) {
        report.error = error.what();
        report.result = HYBRIDCLR_DUMP_ERROR;
    } catch (...) {
        report.error = "Unexpected native/C++ exception during capture";
        report.result = HYBRIDCLR_DUMP_ERROR;
    }
    if (!report.complete && report.result == HYBRIDCLR_DUMP_OK) report.result = HYBRIDCLR_DUMP_INCOMPLETE;
    if (!report.directory.empty()) {
        std::string error;
        if (!write_manifest(report, config, error)) {
            log("%s", error.c_str());
            report.result = HYBRIDCLR_DUMP_ERROR;
        }
    }
    log("Capture finished: result=%d, complete=%s, %s", report.result,
        report.complete ? "true" : "false", report.error.c_str());
    return report.result;
}

} // namespace hcd
