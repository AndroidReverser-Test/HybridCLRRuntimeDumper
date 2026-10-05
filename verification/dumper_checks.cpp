// Test-only same-TU seam for the anonymous-namespace types and helpers. Do not
// compile src/dumper.cpp separately into this target; no production export is added.
#include "../src/dumper.cpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <sys/uio.h>

extern "C" const void* hcd_raw_fixture_vtable();

namespace {
struct FixtureRaw {
    const void* vptr;
    const uint8_t* data;
    uint32_t length;
    uint32_t pad;
    const uint8_t* end;
};
static_assert(sizeof(FixtureRaw) == 32 && offsetof(FixtureRaw, data) == 8 &&
              offsetof(FixtureRaw, length) == 16 && offsetof(FixtureRaw, end) == 24);

void pe_header(std::vector<uint8_t>& bytes) {
    // Deliberately not a full DLL: owner discovery needs only MZ/e_lfanew/PE.
    bytes[0] = 'M'; bytes[1] = 'Z';
    const uint32_t pe_offset = 0x40, signature = 0x00004550;
    std::memcpy(bytes.data() + 0x3c, &pe_offset, sizeof(pe_offset));
    std::memcpy(bytes.data() + pe_offset, &signature, sizeof(signature));
}

struct TemporaryOutput {
    std::string path;
    explicit TemporaryOutput(const char* parent) : path(std::string(parent) + "/hcd-dumper-checks-XXXXXX") {
        if (!::mkdtemp(path.data())) throw std::runtime_error("mkdtemp: " + std::string(std::strerror(errno)));
    }
    ~TemporaryOutput() {
        for (const char* suffix : {".dll.partial", ".dll", ".dll.invalid.bin"})
            ::unlink((path + "/limit" + suffix).c_str());
        ::rmdir(path.c_str());
    }
};

bool missing_file(const std::string& path) {
    struct stat info{};
    return ::lstat(path.c_str(), &info) < 0 && errno == ENOENT;
}

struct FixtureAssembly;
struct FixtureImage {
    const char* name;
    const FixtureAssembly* owner;
    uint32_t token;
    uint32_t pad;
};
struct FixtureAssembly {
    uintptr_t unused;
    const FixtureImage* image;
};
static_assert(offsetof(FixtureImage, name) == 0 && offsetof(FixtureImage, owner) == 8 &&
              offsetof(FixtureImage, token) == 16 && offsetof(FixtureAssembly, image) == 8);

unsigned assembly_getter_calls = 0, name_getter_calls = 0;
const hcd::Il2CppImage* fake_assembly_image(const hcd::Il2CppAssembly* assembly) {
    ++assembly_getter_calls;
    return reinterpret_cast<const hcd::Il2CppImage*>(reinterpret_cast<const FixtureAssembly*>(assembly)->image);
}
const char* fake_image_name(const hcd::Il2CppImage* image) {
    ++name_getter_calls;
    return reinterpret_cast<const FixtureImage*>(image)->name;
}
} // namespace

int main(int argc, char** argv) {
    unsigned passed = 0, failed = 0;
    const auto check = [&](const char* name, bool ok, const std::string& detail = "") {
        if (ok) ++passed;
        else { ++failed; std::printf("FAIL %s%s%s\n", name, detail.empty() ? "" : ": ", detail.c_str()); }
    };
    const auto finish = [&] { std::printf("PASS %u FAIL %u\n", passed, failed); return failed ? 1 : 0; };
    if (argc > 2) {
        std::printf("Usage: %s [writable_temporary_parent]\n", argv[0]);
        return 1;
    }
    try {
        const void* vtable = hcd_raw_fixture_vtable(); // Also keeps the SHARED fixture linked and mapped.
        hcd::Module module;
        hcd::Memory memory;
        std::string error;
        const bool mapped = module.find("libhybridclr_raw_fixture.so", error);
        check("real raw fixture Module::find", mapped, error);
        if (!mapped) return finish();
        const bool refreshed = memory.refresh(error);
        check("Memory::refresh", refreshed, error);
        if (!refreshed) return finish();

        const uint64_t probe = UINT64_C(0x123456789abcdef0);
        uint64_t kernel_copy = 0, memory_copy = 0;
        iovec local{&kernel_copy, sizeof(kernel_copy)};
        iovec remote{const_cast<uint64_t*>(&probe), sizeof(probe)};
        const ssize_t read = ::syscall(SYS_process_vm_readv, ::getpid(), &local, 1, &remote, 1, 0);
        check("self process_vm_readv and Memory::read after refresh", read == ssize_t(sizeof(probe)) &&
              kernel_copy == probe && memory.value(hcd::address(&probe), memory_copy) && memory_copy == probe);

        std::array<uintptr_t, 16> slots{};
        bool all_inside = module.contains(hcd::address(vtable), sizeof(slots)) &&
                          memory.read(hcd::address(vtable), slots.data(), sizeof(slots));
        for (uintptr_t slot : slots)
            all_inside &= module.contains(slot, 4, true) && memory.executable(slot, 4);
        check("all 16 vtable pointers are fixture module executable code", all_inside);
        if (!all_inside) return finish();

        std::vector<uint8_t> bytes_a(96 * 1024), bytes_b(32 * 1024);
        pe_header(bytes_a); pe_header(bytes_b);
        FixtureRaw raw_a{vtable, bytes_a.data(), uint32_t(bytes_a.size()), 0, bytes_a.data() + bytes_a.size()};
        FixtureRaw raw_b{vtable, bytes_b.data(), uint32_t(bytes_b.size()), 0, bytes_b.data() + bytes_b.size()};
        std::array<uintptr_t, hcd::profile::kRawOwnerBytes / sizeof(uintptr_t)> owner{};
        hcd::Config config;
        config.automatic_discovery = true;
        config.dump_pdb = false;
        config.max_file_size = 64 * 1024;
        hcd::Candidate raw_candidate;
        hcd::Report raw_report;
        hcd::profile::Layout selected;
        uintptr_t raw_object = 0;
        const auto raw_case = [&](const char* name, bool accepted, uintptr_t expected = 0,
                                  size_t offset = 0, const char* reason = nullptr) {
            raw_candidate = {};
            raw_candidate.name = "SameNativeName.dll";
            raw_candidate.hybrid_image = hcd::address(owner.data());
            raw_candidate.layout.image_raw = 0x78;
            raw_candidate.layout.raw_data = 0x80;
            raw_candidate.layout.raw_length = 0x88;
            raw_candidate.layout.raw_end = 0x90;
            raw_report = {};
            raw_report.module = module;
            selected = {};
            raw_object = 0;
            error.clear();
            hcd::refresh(memory);
            const bool found = hcd::auto_raw_field(raw_candidate, false, raw_report,
                                                  memory, raw_object, selected, error);
            bool ok = found == accepted;
            if (accepted) {
                ok &= error.empty() && raw_object == expected && selected.image_raw == offset &&
                      selected.raw_data == offsetof(FixtureRaw, data) &&
                      selected.raw_length == offsetof(FixtureRaw, length) &&
                      selected.raw_end == offsetof(FixtureRaw, end) && !raw_report.discovery_evidence.empty() &&
                      raw_candidate.sources == std::vector<std::string>{"SEMANTIC_DLL_LOADER_AND_RAW_OWNER"};
            } else {
                ok &= !error.empty() && raw_report.discovery_evidence.empty() && raw_candidate.sources.empty();
                if (reason) ok &= error.find(reason) != std::string::npos;
            }
            check(name, ok, error);
        };

        owner[0x18 / 8] = hcd::address(&raw_a);
        owner[0x28 / 8] = hcd::address(&raw_b);
        raw_case("96 KiB and 32 KiB owners remain ambiguous at a 64 KiB limit", false, 0, 0, "Ambiguous");
        std::swap(owner[0x18 / 8], owner[0x28 / 8]);
        raw_case("oversized owner ambiguity is independent of owner order", false, 0, 0, "Ambiguous");

        owner.fill(0);
        owner[0x18 / 8] = hcd::address(&raw_a);
        raw_case("unique oversized raw is discovered before the copy limit", true, hcd::address(&raw_a), 0x18);
        {
            TemporaryOutput output(argc == 2 ? argv[1] : ".");
            raw_report.directory = output.path;
            hcd::Blob blob;
            const std::atomic<bool> cancelled{false};
            hcd::dump_blob(blob, raw_object, hcd::address(owner.data()) + selected.image_raw, false,
                           "limit", selected, config, raw_report, memory, cancelled);
            check("oversized unique dump is PARTIAL with a limit failure", blob.status == "PARTIAL" &&
                  blob.reason.find("limit") != std::string::npos && blob.raw.object == hcd::address(&raw_a) &&
                  blob.raw.length == bytes_a.size(), blob.reason);
            check("oversized dump cannot report copied bytes or success", blob.written == 0 &&
                  !blob.coverage_complete && !blob.format.valid && blob.filename.empty() &&
                  blob.chunks.empty() && blob.output_hash.empty() && blob.live_hash.empty());
            check("oversized dump creates neither partial nor published files",
                  missing_file(output.path + "/limit.dll.partial") && missing_file(output.path + "/limit.dll") &&
                  missing_file(output.path + "/limit.dll.invalid.bin"));
        }

        FixtureRaw same_size = raw_b;
        owner[0x18 / 8] = hcd::address(&raw_b);
        owner[0x28 / 8] = hcd::address(&same_size);
        raw_case("distinct equal-size owners remain ambiguous even with identical payload", false, 0, 0, "Ambiguous");
        owner.fill(0);
        raw_case("no raw owner does not certify absence", false, 0, 0, "absence is not certified");

        FixtureRaw bad_pne = raw_a;
        --bad_pne.end;
        owner[0x18 / 8] = hcd::address(&bad_pne);
        raw_case("bad P/N/E alone is not selected", false);
        owner[0x28 / 8] = hcd::address(&raw_b);
        raw_case("bad P/N/E prevents a false unique valid owner", false, 0, 0, "Invalid discovered raw descriptor");

        owner.fill(0);
        owner[0x28 / 8] = hcd::address(&raw_b);
        bytes_b[0] = 0;
        raw_case("valid P/N/E but missing MZ is rejected", false);
        owner[0x18 / 8] = hcd::address(&raw_a);
        raw_case("unknown raw format cannot be ignored beside a valid DLL", false, 0, 0, "Unknown format");
        owner[0x18 / 8] = 0;
        bytes_b[0] = 'M';
        bytes_b[0x40] = 0;
        raw_case("valid P/N/E but missing PE signature is rejected", false);
        bytes_b[0x40] = 'P';
        const uint32_t outside = uint32_t(bytes_b.size());
        std::memcpy(bytes_b.data() + 0x3c, &outside, sizeof(outside));
        raw_case("PE signature offset outside the raw range is rejected", false);
        pe_header(bytes_b);
        for (size_t offset : {size_t(0x18), size_t(0x28)}) {
            owner.fill(0);
            owner[offset / 8] = hcd::address(&raw_b);
            raw_case(offset == 0x18 ? "unique owner at +0x18" : "unique owner moved to +0x28",
                     true, hcd::address(&raw_b), offset);
        }

        const std::atomic<bool> not_cancelled{false}, cancelled{true};
        check("real raw vptr/vtable/loader evidence survives the final audit",
              hcd::audit_auto_evidence(raw_report, memory, not_cancelled) && !raw_report.discovery_evidence_unchanged);
        std::array<uint8_t, 16> observed{1, 2, 3, 4};
        hcd::Report audit;
        check("Report audit and completion flags default to false", !audit.discovery_evidence_unchanged &&
              !audit.complete && !audit.cancelled && !audit.all_registered_inputs_exported && !audit.snapshot_unchanged);
        audit.discovery_evidence.push_back({"observed_data", hcd::address(observed.data()), observed.size(),
                                            hcd::sha256(observed.data(), observed.size())});
        hcd::refresh(memory);
        check("matching observed semantic evidence audits true without mutating Report",
              hcd::audit_auto_evidence(audit, memory, not_cancelled) && !audit.discovery_evidence_unchanged);
        observed[0] ^= 1;
        check("changed observed semantic evidence audits false",
              !hcd::audit_auto_evidence(audit, memory, not_cancelled) && !audit.discovery_evidence_unchanged);
        observed[0] ^= 1;
        audit.discovery_evidence[0].address = 1;
        check("unreadable semantic evidence audits false",
              !hcd::audit_auto_evidence(audit, memory, not_cancelled) && !audit.discovery_evidence_unchanged);
        audit.discovery_evidence[0].address = hcd::address(observed.data());

        std::array<uint8_t, 20> loader_code{};
        if (!memory.read(slots[2], loader_code.data(), loader_code.size()))
            throw std::runtime_error("Cannot observe the fixture loader binding");
        hcd::Report bindings;
        bindings.bindings.push_back({"fixture_loader", "TEST_OBSERVED_CODE", slots[2], slots[2] - module.bias,
                                     loader_code.size(), std::string(64, '0'),
                                     hcd::sha256(loader_code.data(), loader_code.size())});
        check("binding audit uses the observed actual hash, not configured expected hash",
              hcd::audit_auto_evidence(bindings, memory, not_cancelled) && !bindings.discovery_evidence_unchanged);
        const std::string actual_hash = bindings.bindings[0].actual_hash;
        bindings.bindings[0].actual_hash = std::string(64, '0');
        check("mismatched binding audits false",
              !hcd::audit_auto_evidence(bindings, memory, not_cancelled) && !bindings.discovery_evidence_unchanged);
        bindings.bindings[0].actual_hash = actual_hash;
        bindings.bindings[0].address = 1;
        check("unreadable binding audits false",
              !hcd::audit_auto_evidence(bindings, memory, not_cancelled) && !bindings.discovery_evidence_unchanged);
        bindings.bindings[0].address = slots[2];

        // Pre-set cancellation is deterministic; no scheduler-dependent hash/thread race.
        hcd::Report empty_audit;
        for (hcd::Report* target : {&empty_audit, &audit, &bindings}) {
            bool threw = false;
            try { target->discovery_evidence_unchanged = hcd::audit_auto_evidence(*target, memory, cancelled); }
            catch (const hcd::Cancelled&) { threw = true; }
            check(target == &empty_audit ? "cancelled empty audit throws before caller flag assignment" :
                  target == &audit ? "cancelled semantic audit throws before caller flag assignment" :
                                    "cancelled binding-only audit throws before caller flag assignment",
                  threw && !target->discovery_evidence_unchanged && !target->complete && !target->cancelled &&
                  !target->all_registered_inputs_exported && !target->snapshot_unchanged);
        }

        // These are fixture layouts, not target offsets. The hot back-pointer is
        // beyond the raw-owner prefix, and no MethodInfo/private query is needed.
        FixtureAssembly hot_assembly{}, aot_assembly{};
        FixtureImage hot_image{"FixtureHot.dll", &hot_assembly, (256u << 22) | 1u, 0};
        FixtureImage aot_image{"FixtureAot.dll", &aot_assembly, 1, 0};
        hot_assembly.image = &hot_image;
        aot_assembly.image = &aot_image;
        std::array<uintptr_t, hcd::profile::kImageAssociationBytes / sizeof(uintptr_t)> hot{};
        std::array<uintptr_t, hcd::profile::kImageAssociationBytes / sizeof(uintptr_t)> supplement{};
        hot[0x100 / 8] = hcd::address(&hot_image);
        supplement[40 / 8] = hcd::address(&aot_assembly);
        config.profile.layout.il2cpp_image_assembly = offsetof(FixtureImage, owner);
        config.profile.layout.il2cpp_image_token = offsetof(FixtureImage, token);
        config.profile.layout.il2cpp_image_name = offsetof(FixtureImage, name);
        config.profile.layout.assembly_image = offsetof(FixtureAssembly, image);
        config.profile.layout.aot_target_assembly = 40;
        hcd::Report associated;
        associated.before.hot[256] = hcd::address(hot.data());
        associated.before.aot.push_back(hcd::address(supplement.data()));
        hcd::Api api;
        api.assembly_image = fake_assembly_image;
        api.image_name = fake_image_name;
        check("auto tests supply no private query or class/method enumeration pointers",
              !api.underlying_image && !api.find_aot_image && !api.class_count && !api.image_class && !api.class_methods);
        assembly_getter_calls = name_getter_calls = 0;
        hcd::discover(associated, api, memory, config, not_cancelled);
        bool verified = associated.candidates.size() == 2;
        for (const auto& candidate : associated.candidates) {
            const bool is_hot = candidate.kind == "HOT_UPDATE";
            verified &= candidate.registered && candidate.query_confirmed && candidate.association_verified &&
                        candidate.error.empty() && candidate.method == 0 && candidate.private_query_status == "NOT_REQUESTED" &&
                        candidate.association_route == "SEMANTIC_REGISTRY_PUBLIC_API" &&
                        candidate.name == (is_hot ? hot_image.name : aot_image.name) &&
                        candidate.assembly == hcd::address(is_hot ? &hot_assembly : &aot_assembly) &&
                        candidate.il2cpp_image == hcd::address(is_hot ? &hot_image : &aot_image) &&
                        (is_hot ? candidate.registry_index == 256 && candidate.layout.hot_il2cpp_image == 0x100 :
                                  candidate.kind == "AOT_SUPPLEMENT" && candidate.layout.aot_target_assembly == 40);
        }
        check("hot slot 256 and AOT token 1 use SEMANTIC_REGISTRY_PUBLIC_API", verified);
        check("public assembly and name getters are actively invoked exactly twice each",
              assembly_getter_calls == 2 && name_getter_calls == 2);

        hcd::Report wrong_public;
        wrong_public.before = associated.before;
        api.assembly_image = [](const hcd::Il2CppAssembly*) -> const hcd::Il2CppImage* {
            ++assembly_getter_calls;
            return nullptr;
        };
        assembly_getter_calls = name_getter_calls = 0;
        hcd::discover(wrong_public, api, memory, config, not_cancelled);
        bool rejected = wrong_public.candidates.size() == 2;
        for (const auto& candidate : wrong_public.candidates)
            rejected &= candidate.association_verified && !candidate.query_confirmed && candidate.method == 0 &&
                        candidate.private_query_status == "NOT_REQUESTED" &&
                        candidate.error.find("assembly_get_image disagrees") != std::string::npos;
        check("public assembly getter disagreement rejects otherwise valid associations",
              rejected && assembly_getter_calls == 2 && name_getter_calls == 0);

        wrong_public = {};
        wrong_public.before = associated.before;
        api.assembly_image = fake_assembly_image;
        api.image_name = [](const hcd::Il2CppImage*) -> const char* {
            ++name_getter_calls;
            return reinterpret_cast<const char*>(uintptr_t(1));
        };
        assembly_getter_calls = name_getter_calls = 0;
        hcd::discover(wrong_public, api, memory, config, not_cancelled);
        rejected = wrong_public.candidates.size() == 2;
        for (const auto& candidate : wrong_public.candidates)
            rejected &= candidate.association_verified && !candidate.query_confirmed && candidate.method == 0 &&
                        candidate.private_query_status == "NOT_REQUESTED" &&
                        candidate.error.find("Unreadable or unterminated image name") != std::string::npos;
        check("unreadable public name getter result is not replaced by the native field",
              rejected && assembly_getter_calls == 2 && name_getter_calls == 2);
    } catch (const hcd::Cancelled&) { check("unexpected cancellation", false); }
      catch (const std::exception& exception) { check("fixture exception", false, exception.what()); }
    return finish();
}
