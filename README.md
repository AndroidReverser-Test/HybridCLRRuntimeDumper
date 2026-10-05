# HybridCLRRuntimeDumper

Android ARM64 in-process raw DLL recovery through public IL2CPP calls and bounded
HybridCLR semantic discovery, with an explicit legacy profile mode.

This is an injectable shared library, like the native part of
`../PtraceIl2cppDumper`. An external ptrace injector selects the PID and loads
`libhybridclr_dumper.so`. This project does not implement a ptrace injector,
install loading hooks, scan the whole heap, execute application methods, or
reconstruct DLLs from interpreter IR.

Use only with applications you are authorized to inspect. **Auto has now passed
device injection and independent host verification** against the current
`com.plantsvszombies3.mengxing` binary. This is single-build validation, not
validation across different real HybridCLR framework versions. See the current
summary below and [Portable Validation](verification/PORTABLE_VALIDATION.md).
[Device Validation](verification/DEVICE_VALIDATION.md) separately records the
2026-10-05 **legacy profile** sessions; those are not auto evidence.

Chinese end-to-end workflow: [DLL Dump Workflow (Chinese)](DLL_Dump_Workflow_CN.md).

## Recoverable Scope

- Currently registered hot-update DLLs whose complete raw file copy survives.
- Registered supplementary AOT DLL inputs, including SUPERSET inputs.
- Optional Portable PDB files, saved separately from DLLs.

Ordinary AOT assemblies without supplementary raw data are not enumerated by
this registry-driven implementation. Their original DLLs cannot be recovered
by these APIs. The report does not invent a complete ordinary-AOT exclusion list.
Unloaded history, files not yet loaded, freed failed inputs, pre-stripping AOT
DLLs, encrypted resource containers, and IR-only runtime changes are out of scope.

"All" means the union of currently retained hot-update and supplementary AOT
raw inputs, not every original DLL in the application.

## Runtime Requirements

1. Android `arm64-v8a`, a little-endian 64-bit process, and the matching SO build.
2. IL2CPP/HybridCLR initialization and the relevant DLL loading have completed.
3. For certified captures, a real application-controlled loading/lifetime gate prevents relevant loads,
   raw destruction and raw modification throughout discovery, copying and audit.
4. The injector resumes the process threads after loading this SO. Do not park a
   metadata-lock holder and then make the worker call lock-taking runtime APIs.
5. The target can read its own mappings and use at least one of self
   `process_vm_readv` or `/proc/self/mem` for failure-reporting descriptor and
   raw payload reads.
6. The configuration file is readable and the selected output directory is
   writable by the target application's UID.

`stable_window_confirmed=1` is a declaration of requirement 3, not a gate
implementation. Sleep, two equal reads, or an idle-looking screen are not a
lifetime guarantee. This project cannot infer an application-specific gate.
Do not hold HybridCLR's own metadata lock across the call: runtime calls,
including the legacy profile queries, may acquire it internally. Use a
higher-level application loading gate instead.

In **both discovery modes**, raw payload copying and the second live hash pass
use failure-reporting kernel reads through self `process_vm_readv`, with
`/proc/self/mem` as a fallback, rather than dereferencing live payloads with
`memcpy`. Reads and pointer comparisons normalize Android top-byte tags; the
manifest retains original pointers. This is not PAC authentication. Failed or
short reads are reported, never replaced with zero-filled data. This reduces
native-fault risk from freed or unmapped payloads, but adds no lifetime lock and
does not create a coherent snapshot. Incorrect runtime function ABIs or invalid
objects passed to runtime APIs can still crash the target. No process-wide
SIGSEGV handler is installed. A real gate remains mandatory for certification.

An authorized, explicitly ungated device experiment can instead set
`stable_window_confirmed=0` and `allow_ungated_capture=1`. The latter defaults to
false. This is not a synchronization workaround. Mode-specific code checks,
descriptor, hash and registry checks remain enabled. Such a capture never
returns `HYBRIDCLR_DUMP_OK`, and its manifest never certifies a complete stable
snapshot, even if all files pass. Use `verification/auto-device.conf` for the
recommended auto experiment; `verification/device.conf` is the legacy sample
profile experiment.

## Discovery Modes

**Recommended: explicitly select `discovery_mode=auto`.** Start from
`hybridclr_dump.auto.conf.example` for a real application-controlled gate, or
`verification/auto-device.conf` for an authorized ungated experiment. These
files contain no function RVAs, expected code hashes, registry addresses or
object layout inputs. `profile.name` is optional in auto mode and defaults to
`arm64-semantic-metadata-v2`; it labels the discovery route, not a known binary.

Auto rejects `function.*`, `registry.*`, `evidence.*`, `layout.*` and
`profile.analysis_sha256`. Do not combine a legacy profile with auto controls.
Unknown code, unsupported shapes, ambiguous matches or exceeded bounds fail
closed. There is no silent profile fallback or sample-address fallback.

Auto requires only these seven **real dynamic exports from the selected ELF**:

```text
il2cpp_domain_get
il2cpp_assembly_get_image
il2cpp_image_get_name
il2cpp_thread_current
il2cpp_thread_attach
il2cpp_thread_detach
il2cpp_resolve_icall
```

After establishing the IL2CPP thread attachment, it calls
`il2cpp_resolve_icall("HybridCLR.RuntimeApi::PreJitClass(System.Type)")` only to
obtain an entry address. **It never calls `PreJitClass` or the analyzed HybridCLR
parser/helper code.**
Read-only bounded A64 CFG analysis follows the supported mask-table/token and
hot-array access semantics and the AOT vector walk. Instruction analysis of the
exported getters identifies the `assembly_image` and `image_name` fields.

For each registered hot object `H`, only its first 512 bytes are inspected for
a unique native image back-pointer, cross-checked by token, owner and getter
relationships. Only the first 128 bytes of each registered HybridCLR image
object are inspected for a unique retained raw object. The first 16 RawImage
vtable slots are inspected as code, not invoked; their supported load prefix
identifies **data64 / length32 / end64**. P/N/E consistency, readable ranges and
`MZ` / `PE` magic positively identify a DLL candidate before copying. This is
bounded object-prefix inspection, not a whole-heap scan.

Raw discovery does **not** filter candidates using `max_file_size`; that setting
limits copying only. A second identified raw owner remains ambiguous even when
it exceeds the copy limit. An identified raw-like owner with unsupported loader
fields, invalid P/N/E, bad PE headers or an unknown format fails closed; it is
not ignored to select another owner and manufacture a unique match.

| Semantic Discovery Limit | Bound |
| --- | --- |
| Registry CFG depth / functions | 3 / 32 |
| Instructions per function / total visits | 128 / 4096 |
| Getter and raw load prefixes | 32 instructions, up to 8 direct `B` thunks |
| RawImage vtable | First 16 readable, module-executable slots; Itanium vptr at `+0` |

The supported ABI still requires metadata-v2's mask table and shift 22 token
decoding, 1024 hot slots, a three-pointer begin/end/capacity AOT vector and the
Itanium vptr-at-zero layout. PAC, PLT/indirect entry thunks, different containers
and unknown code shapes are unsupported. Auto adapts only supported ABI changes
such as RVA relocation, compiler register allocation, GOT versus direct address
materialization and field positions. It is **not arbitrary-version support**.
The current binary's device capture, same-sample IDA/offline checks and synthetic
parser/fake-reader tests have passed. None demonstrates compatibility with
different real framework versions; those still require separate device tests.

The auto examples default to `dump_pdb=0`. With `dump_pdb=1`, auto can positively
discover a nonempty Portable PDB raw object, but cannot certify that a PDB is
absent. Failure to find a unique supported object yields `NOT_DISCOVERED`, making
the requested capture incomplete. A legacy profile knows the PDB field and can
report `NOT_PRESENT` when it reads a null pointer there.

## Legacy Profile (Explicit Fallback)

Omitting `discovery_mode` continues to select `profile` for deployed complete
configurations; `discovery_mode=profile` selects it explicitly. Use this route
only as a separately reviewed alternative when auto cannot recognize the target
and a matching supported-ABI profile has been analyzed. Auto never selects it
on your behalf. The old sample is not a profile for an arbitrary new build.

`hybridclr_dump.conf.example` and `verification/device.conf` contain the complete
legacy sample addresses/layout recovered from:

- `../HybridCLR_SO_Analysis_Guide.md`
- `../HybridCLR_Runtime_DLL_Recovery_Plan.md`
- `D:\sofixer\libil2cpp_fix.so.i64`, image base zero
- Analysis input SHA-256:
  `809544844f1dd046148ea5fcee35a0414f0256bdc995e824963ca0ff4a769da7`

The analysis input is a fixed ELF snapshot; its hash is NOT claimed to be the
runtime APK library hash. The manifest stores the runtime GNU build ID when
available, the load bias and the actual checked code hashes.

`src/profile.h` defines function/ABI roles, layout storage, configuration keys
and supported token rules, not a built-in sample address/fingerprint profile.
Legacy profile mode requires 11 functions with three entries each, three code
evidence locations, two registry RVAs and the original 14 layout fields. The new
`layout.assembly_image` is optional and defaults to `0`, preserving already
deployed profiles that used the assembly image pointer at `+0`. All original
required values must still be present; no missing entry loads a sample profile.

In profile mode the project checks every configured API entry, the two HybridCLR
queries, and configured code that establishes raw/index layout. A mismatched
entry aborts before invoking runtime APIs. There is no ignore-fingerprint flag.
The supplied sample checks short API stubs using 16 bytes, including neighboring instructions.
Already installed instrumentation can therefore cause a deliberate rejection.

In both modes, named resolution reads the selected live ELF's `PT_DYNAMIC`,
dynsym/dynstr and SysV/GNU hash tables. It does not confuse a name string with a
real export or accidentally resolve another Unity module. **Only profile mode** lets
missing names fall back to the checked configuration RVA. Its named functions
must also be at the configured expected address. C++ semantic names are not
passed to `dlsym` as if they were exports. `il2cpp_domain_get_assemblies` is
neither resolved nor invoked, and
there is no RVA fallback or configuration key for it.

| Configuration Key | Purpose |
| --- | --- |
| `function.<name>.rva` | RVA of each required target runtime function |
| `function.<name>.fingerprint_length` | Number of entry bytes hashed |
| `function.<name>.sha256` | Required code fingerprint |
| `evidence.<name>.rva` / `.bytes_hex` | Read-only layout/code evidence, never called |
| `registry.hot.rva` | Start of the 1024-slot hot-update registry |
| `registry.aot_vector.rva` | Consecutive begin/end/capacity pointer slots |
| `layout.<name>` | Original 14 required field offsets, including explicit zero values |
| `layout.assembly_image` | Optional assembly-to-image field offset, default `0` |

All function addresses use ELF load bias plus RVA. Heap object pointers are
already runtime addresses and are never rebased again. All configured layout
offsets are profile-specific, not a general HybridCLR or Unity ABI. Fingerprints are
guards against wrong entries, not a proof that a vendor has not modified other
code. A different build using profile mode needs a newly analyzed configuration,
not just new hashes. Function signatures, 1024 hot slots and token encoding still have to
match the supported ABI; configuration does not infer a different ABI.

## Build

Only the Android NDK, CMake and Ninja are required. No APK, Gradle, Java, xDL,
OpenSSL or HybridCLR source build is required.

Example PowerShell commands, with installed tool versions substituted:

```powershell
$ndk = "D:/androidSDK/ndk/<installed-version>"
$cmake = "D:/androidSDK/cmake/3.22.1/bin/cmake.exe"
$ninja = "D:/androidSDK/cmake/3.22.1/bin/ninja.exe"
& $cmake -S "D:/hotupdata_test/HybridCLRRuntimeDumper" -B "D:/hotupdata_test/HybridCLRRuntimeDumper/build/arm64" -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" "-DCMAKE_TOOLCHAIN_FILE=$ndk/build/cmake/android.toolchain.cmake" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29 -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
& $cmake --build "D:/hotupdata_test/HybridCLRRuntimeDumper/build/arm64"
```

Expected output:

```text
build/arm64/libhybridclr_dumper.so
```

The main SO links with `--exclude-libs,ALL` to keep static libc++ symbols from
polluting the application's symbol namespace. The linker requests
16 KiB-compatible ELF segment alignment and does not assume
4 KiB pages for its file mappings. Build using a current NDK for current Android
devices. NDK `27.0.12077973`, CMake `3.22.1`, Android API 29 and static libc++ were
used for the verified device build.

Constructor autostart remains **ON** by default. For application-controlled
entry only, configure with
`-DHYBRIDCLR_DUMPER_AUTOSTART=OFF` to omit constructor-based startup.

Configure with `-DHYBRIDCLR_DUMPER_BUILD_TESTS=ON` for these optional test targets:

| Target | Coverage | Current Build Result |
| --- | --- | --- |
| `hybridclr_discovery_checks` | Synthetic parser/fake-reader and optional offline ELF semantics | `PASS 98 FAIL 0` |
| `hybridclr_native_checks` | Mode-specific configuration, PE metadata and kernel-read regressions | `PASS 31 FAIL 0` |
| `hybridclr_dumper_checks` | Raw-owner ambiguity/copy-limit and public-association regressions | `PASS 36 FAIL 0` |

These tests do not invoke target runtime APIs or discovered target code. Offline
input addresses are test arguments, not auto capture configuration inputs.
`hybridclr_dumper_checks` also requires the generated
`libhybridclr_raw_fixture.so`. Deploy both to `/data/local/tmp` and run the test
in an authorized device shell with a writable temporary parent:

```sh
LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/hybridclr_dumper_checks /data/local/tmp
```

Counts describe this tested build, not a fixed total for future revisions. Host
manifest regression tests are separate; their evolving totals belong in the
validation record, not the device-capture file count.

`build/arm64` remains a valid build directory. To keep new validation artifacts
separate from historical profile outputs, use a fresh directory such as
`build/portable-arm64` for both the configure and build commands. Always deploy
the newly built SO, not an old artifact found in a previous directory.

## Injection Startup

1. Establish the application loading/lifetime gate for a certified capture, or
   explicitly choose an authorized ungated experiment without claiming a gate.
2. Place `hybridclr_dump.auto.conf.example` at the target app's
   `files/hybridclr_dump.conf`, with the appropriate settings and app-readable
   ownership/permissions. For an explicitly authorized ungated experiment, use
   `verification/auto-device.conf` instead and do not claim a held gate.
3. Use the same external injector workflow as `PtraceIl2cppDumper`, selecting
   the target PID and loading `libhybridclr_dumper.so`. Injector command-line
   flags depend on the particular injector/version; none are invented here.
4. Resume all target threads. If using a real gate, keep it held until completion.
5. Follow logcat tag `HybridCLRDump` and inspect the session's `manifest.json`.

The constructor only starts a native bootstrap worker. On that worker,
`/proc/self/cmdline` supplies the package name; a `:remote` suffix is removed.
The Android user ID is calculated from `getuid()/100000`.

Configuration lookup:

```text
/data/user/<user>/<package>/files/hybridclr_dump.conf
/data/data/<package>/files/hybridclr_dump.conf  (user 0 fallback)
```

Missing configuration does not start a capture. Unknown/duplicate keys,
non-ASCII text, invalid values, missing mode-specific requirements, auto/manual
profile mixing, or an unconfirmed stable window without the explicit
experimental opt-in are rejected. Missing RVAs/fingerprints/original layouts
reject profile mode; they are not inputs in auto mode.
Custom process names, isolated UIDs, and unusual app data locations should use
the exported API instead of relying on this path inference. Configuration is
loaded once per admitted capture, including exported-API captures. Editing it
after `hybridclr_dump_start` returns does not affect that capture and does not
trigger another capture automatically.

Recommended strict auto configuration, only when a real gate is held:

```ini
discovery_mode=auto
stable_window_confirmed=1
allow_ungated_capture=0
module_name=libil2cpp.so
initialization_timeout_seconds=30
chunk_size=262144
max_file_size=536870912
dump_pdb=0
```

Unlike profile execution controls alone, the block above is sufficient auto
configuration; no target-specific fields should be added. For legacy profile
mode, start from its complete file described in the fallback section instead.
Integers accept unsigned decimal or `0x`/`0X` hexadecimal. Negative values,
overflow, misalignment, incomplete profile hashes, unknown keys and duplicate
keys are rejected. In profile mode `layout.class_image=0` is valid but remains
required; only the new `layout.assembly_image` may be omitted with default `0`.

An optional `output_directory` must be absolute and writable by the target.
Otherwise the root is `<configuration parent>/hybridclr_dll_dump`, which is
`files/hybridclr_dll_dump` for the injection configuration. Each capture creates a new
`<unix-ms>-<pid>-<sequence>` subdirectory. No previous capture is overwritten.

`chunk_size` is 64 KiB through 1 MiB. `max_file_size` is at most `UINT32_MAX`,
matching the verified 32-bit raw length; it applies at copy time, not to auto
owner identification or uniqueness. Zero execution chunk/size/timeout
values in the configuration select defaults; profile function and registry RVAs
have no default and cannot be zero. The initialization timeout bounds waits for
the module/domain and, in auto mode, the icall entry; it does not interrupt a
lock-taking native call or impose a whole-capture timeout.

## Exported API

`include/hybridclr_dumper.h` exposes C ABI version 2. Options specify the absolute
configuration file path and a caller confirmation of the stable window; output,
module, execution settings and discovery mode come from that file. Target RVAs
are configuration inputs only in profile mode; auto discovers them at runtime.
The previous options structure is no longer accepted.

| Function | Meaning |
| --- | --- |
| `hybridclr_dump_run(options)` | Synchronous capture in the current thread |
| `hybridclr_dump_start(options)` | Load/copy the entire configuration and launch a native worker |
| `hybridclr_dump_state()` | `IDLE`, `RUNNING`, or `FINISHED` |
| `hybridclr_dump_result()` | Last result, or `BUSY` while running |
| `hybridclr_dump_cancel()` | Request cooperative cancellation |

The current `build/portable-arm64/libhybridclr_dumper.so` was observed to export
only these five defined C API symbols, with static C++ symbols hidden. These
dumper exports are distinct from the seven target IL2CPP exports required by auto.

Example for an application-controlled stable window:

```cpp
#include "hybridclr_dumper.h"

// The application's real loading/lifetime gate is already held here.
HybridClrDumpOptions options{};
options.struct_size = sizeof(options);
options.abi_version = HYBRIDCLR_DUMPER_ABI_VERSION;
options.config_path = "/data/user/0/com.example.test/files/hybridclr_dump.conf";
options.stable_window_confirmed = 1;
int result = hybridclr_dump_run(&options);
// The synchronous capture has returned; the application can release its gate.
```

For an asynchronous call, a return value of zero means accepted, not completed.
Keep the application gate held until `state()` is `FINISHED`, then read
`result()`. For certified captures both the options and configuration must confirm
the stable window. Experimental calls may leave the options confirmation at zero
only with the explicit ungated configuration described above. Only one capture
is admitted at a time. The worker attaches to
IL2CPP if necessary, and detaches only an attachment it created. An already
attached application thread is not detached by the synchronous path.

Cancellation takes effect at waits, discovery boundaries and copy blocks after
native functions return. It is not forced native-call cancellation or rollback.
Do not unload this library while any API/bootstrap/worker is active. Even
`FINISHED` is not a thread-join or SO-unload barrier; keep the library loaded.

| Result | Meaning |
| --- | --- |
| `0` | All retained inputs in the declared scope completed, subject to the caller's gate |
| `1` | Capture has unresolved/pending/partial/invalid entries, or is explicitly ungated |
| `-1` | Invalid options |
| `-2` | Another capture is running |
| `-3` | Setup, unsupported/ambiguous discovery, profile, runtime or I/O failure |
| `-4` | Cooperative cancellation |

## Capture Flow

### Recommended Auto Route

1. Load and validate the auto configuration, find the selected loaded module
   using `dl_iterate_phdr`, and bind its seven real dynamic exports. Record
   actual entry hashes, not expected known-binary fingerprints.
2. Obtain the domain and establish the worker's IL2CPP thread attachment.
3. Resolve the `PreJitClass(System.Type)` icall address without invoking it.
   Read its bounded CFG and the exported getters to discover registries and
   identity fields. Reject unsupported or ambiguous discovery.
4. Snapshot every hot registry slot and the AOT vector's valid `[begin,end)`;
   create a candidate for every registered object before per-image calls.
5. Cross-check each hot object's unique native image back-pointer within 512
   bytes, or the AOT target assembly from the vector-walk semantics. Verify the
   token/owner/assembly-image relationships before calling public identity APIs.
6. Call `il2cpp_assembly_get_image` and `il2cpp_image_get_name` to confirm identity.
   Do not call private queries or enumerate classes/methods.
7. Find the unique raw owner within 128 bytes, decode its RawImage vtable load
   prefix and verify data64/length32/end64, readable VMAs and PE magic. Do not
   discard oversized or malformed raw-like owners to obtain false uniqueness.
8. Sequentially kernel-read `[0,length)` in bounded blocks, including original headers,
   section padding, gaps, certificates and overlays. Never substitute
   `SizeOfImage`, the last section end, or zero-filled holes for the raw length.
9. Record each block's exact file offset, written length and SHA-256. Hash the
   live raw again and recheck the raw descriptor/owning image field.
10. Independently inspect the saved PE/CLI/metadata structure and read its
    Assembly name and Module MVID. Compare the native image name separately
    against the metadata Assembly name, and publish complete blobs by rename.
11. If PDB capture was requested, positively discover and copy its independent
    Portable PDB raw object, or report `NOT_DISCOVERED` and an incomplete capture.
12. Recheck registries, associations and actual semantic code/GOT/vptr/vtable
    evidence, then publish the report. No all-assembly enumeration API is used.

### Legacy Profile Differences

Profile mode verifies all 11 configured functions and three layout-code evidence
locations before runtime calls, then reads configured registries and fields.
It additionally checks the configured hot index and nonzero assembly token.
For hot images it enumerates a real non-array class/method and calls
`GetUnderlyingInterpreterImage`; a no-method image uses the verified token/table
route and records `TOKEN_REGISTRY_FALLBACK_NO_METHOD`. For AOT supplementary
images it calls `FindImageByAssembly` and requires the same registered object.
Its known `layout.image_pdb` field permits `NOT_PRESENT` for a null pointer.
The legacy sample uses `Image+0x08` and raw `+0x08/+0x10/+0x18`, not universal
offsets. Full-length kernel copying, structural checks and final audit apply to
both modes.

No `Execute`, `PreJit`, class constructor, business method, `LoadCLIHeader` or
other mutating parser initialization function is deliberately invoked in either
mode. Auto only reads discovered parser/load-prefix code and never invokes it.
Legacy class/method enumeration can perform lazy native initialization and
allocations; public calls, attachment and icall resolution are not a promise of
zero side effects either.

## Output And Failure Reporting

```text
hybridclr_dll_dump/<session>/
    manifest.json
    hot_1_HotUpdate.dll
    aot_2_System.Core.dll
    hot_1_HotUpdate.pdb
```

The names and counts above are illustrative, not a promised 4/21 runtime count.

- `.dll` / `.pdb`: exact-length files with matching copy/live hashes and successful
  supported structural inspection.
- `.partial`: copy, cancellation, descriptor change, hash or I/O failure. Never
  zero-filled or published as a successful DLL.
- `.invalid.bin`: full raw bytes were recovered, but structural inspection
  rejected the format. In auto mode, an unidentified raw format or bad PE magic
  already fails owner discovery; no file is promised for that rejected owner.

Manifest capture statuses include `HOT_UPDATE_COMPLETE`,
`AOT_SUPPLEMENT_COMPLETE`, `PENDING_INITIALIZATION`, `PARTIAL`,
and `INVALID_FORMAT`. PDB status is independent. Every nonempty registry object
has an explicit candidate, even if it cannot safely be exported. Whole-file
SHA-256 plus MVID identifies duplicate content; `duplicate_of_capture_id` records
aliases, but separate source records/files are retained for traceability.

New manifests use **schema 3** and include `discovery_mode`, supported registry
ABI, resolved registry/identity/owner/raw fields, original/tag-normalized
addresses, raw lengths, source routes, code bindings, block/whole hashes,
names/MVIDs, configuration path/text SHA-256 and failures. In auto mode,
`semantic_discovery_evidence` records actual observed code, GOT, vptr and vtable
addresses/lengths/hashes; `semantic_evidence_unchanged` records their final
recheck. These are actual hashes, not expected known-build hashes or an ABI
safety certificate.

Auto records `association_route=SEMANTIC_REGISTRY_PUBLIC_API` and
`private_query_status=NOT_REQUESTED`, **not `MATCH`**. `query_confirmed` denotes
the selected route's confirmation, not proof that private queries ran.
Representative methods are only relevant to profile mode.
`native_name_matches_metadata` independently compares the native name with the
saved DLL's metadata Assembly identity, rather than deriving one from the other.
The manifest explicitly sets `all_process_assemblies_enumerated=false` and
`ordinary_aot_without_raw_enumerated=false`; unknown ordinary AOT assemblies
are not counted as successfully checked or excluded.
`all_registered_inputs_exported` records successful files/associations and an
unchanged registry audit separately from the lifetime-gate precondition.
`experimental_ungated_capture` records the absence of a declared gate.
`complete_within_declared_scope` is false for ungated captures, unresolved registry
objects, changed snapshots/evidence, incomplete DLLs, or requested PDB failures
(including auto `NOT_DISCOVERED`). Equal snapshots
and hashes are change detectors, never replacements for the external gate.

Structural inspection supports standard PE32/PE32+, CLI metadata streams,
standard 0..44 metadata table layouts and Portable PDB root/#Pdb identification.
It accepts Cecil's tables-header Reserved2 value and inactive Sorted-mask bits;
only the Valid mask introduces stored tables and their row layouts.
It deliberately rejects unknown streams, unsupported/extended metadata layouts,
overlapping ranges and invalid indices. It does not verify every IL instruction,
method body, EH clause, signature semantic, resource payload or complete PDB
debug table. Use an independent managed-file analysis tool for those checks.

`verification/verify_captures.py` uses pinned `dnfile`, `pefile` and `dncil`
dependencies to check schema 3 captures while retaining historical schema 2
support, including whole/block hashes, coverage, identity, IL decoding, EH
boundaries and embedded resource bounds.
It does not execute managed code or prove IL semantics. See the device validation
record or the Chinese workflow for installation and invocation commands. Host
PASS validates listed artifacts and report consistency, not live discovery
replay, a lifetime gate or cross-version compatibility. The optional
`--compare-with <reference-session-directory>` additionally
compares actual retained file bytes between sessions, not merely declared hashes.
It rechecks actual length, content hash and Assembly/MVID identity on both sides,
preserving duplicate multiplicity independently of capture IDs and ordering.

The current device helper scripts still use the fixed sample package, Android
user 0 and default output paths; changing a local package variable does not
parameterize them.

## Current Device Validation

The new auto route was exercised in `1791196054447-17919-0` and repeated in
`1791203675884-28745-0`; the legacy profile was regressed in `1791203411317-27900-0`.
All three sessions passed host verification and matched all 25 DLL contents,
including the historical schema 2 baseline. The first auto session summary:

| Item | Observed Result |
| --- | --- |
| Target GNU build ID | `b1ab380823c8af07794776c401e3a6ca57de9441` |
| Process | PID `17919`, still alive after capture and host verification |
| Retained DLLs | 25/25: 4 hot-update + 21 supplementary AOT; 26,188,800 bytes |
| Independent host checks | `PASS`: 116 chunks, 165,802 IL bodies, 6,026 EH clauses |
| Auto inputs / bindings | No manual RVA, field or expected hash inputs; 7 real dynamic exports |
| Candidate association | All 25 use `SEMANTIC_REGISTRY_PUBLIC_API` / `NOT_REQUESTED`; association, public confirmation and native/metadata name checks are true |
| Final audit | Semantic evidence and registry snapshots unchanged; `all_registered_inputs_exported=true` |
| Gate / result | Ungated, `result_code=1`, `complete_within_declared_scope=false` |
| PDB | `DISABLED`, not `NOT_PRESENT`; PDB absence and actual PDB export were not tested |

The currently published SO is `build/portable-arm64/libhybridclr_dumper.so`,
SHA-256 `249e5f09b8b1127c6e320b9352d80fcf76d28076bd703e2724961f7d009cfdec`.
This identifies the dumper artifact, not the target runtime. Consolidated evidence
is recorded in [Portable Validation](verification/PORTABLE_VALIDATION.md), including
the profile regression, auto repeat and 208 successful checks/tests. Current device
coverage remains this one target binary; neither unchanged evidence nor safe
kernel reads certifies a lifetime gate or different real framework versions.

## Source Map

| File | Responsibility |
| --- | --- |
| `src/entry.cpp` | Injection bootstrap, configuration and versioned exported API |
| `src/config.cpp` | Strict mode-specific configuration, mixing rejection and source hash |
| `src/profile.h` | Function/ABI roles and configuration schema, no sample addresses |
| `src/discovery.cpp` / `src/discovery.h` | Bounded A64 semantic registry/getter/raw discovery; never invokes discovered code |
| `src/platform.cpp` | In-process ELF resolution, readable ranges and failure-reporting kernel reads |
| `src/dumper.cpp` | Auto/public and legacy/private routes, registry/evidence audit, copying and schema 3 manifest |
| `src/pe.cpp` | Bounded independent PE/CLI/metadata inspection and identity |
| `src/sha256.cpp` | Streaming SHA-256 without external crypto dependencies |
| `verification/discovery_checks.cpp` | Synthetic parser/fake-reader checks and optional offline ELF checks |
| `verification/dumper_checks.cpp` / `verification/raw_fixture.cpp` | Test-only raw-owner/copy-limit and association fixtures, not production exports |

The project borrows the injected-worker architecture of the local example, not
its memory-snapshot/text-dump implementation or NativeBridge code. The existing
example, HybridCLR checkout, original documents and IDA database are unchanged.
