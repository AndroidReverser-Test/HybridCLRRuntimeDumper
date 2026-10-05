# HybridCLRRuntimeDumper

Android ARM64 in-process raw DLL recovery through active IL2CPP/HybridCLR calls.

This is an injectable shared library, like the native part of
`../PtraceIl2cppDumper`. An external ptrace injector selects the PID and loads
`libhybridclr_dumper.so`. This project does not implement a ptrace injector,
install loading hooks, scan the whole heap, execute application methods, or
reconstruct DLLs from interpreter IR.

Use only with applications you are authorized to inspect. The project was
written without building, running, or testing it, as requested.

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
3. A real application-controlled loading/lifetime gate prevents relevant loads,
   raw destruction and raw modification throughout discovery, copying and audit.
4. The injector resumes the process threads after loading this SO. Do not park a
   metadata-lock holder and then make the worker call lock-taking runtime APIs.
5. The target can read its own mappings and use at least one of self
   `process_vm_readv` or `/proc/self/mem` for failure-reporting descriptor reads.
6. The configuration file is readable and the selected output directory is
   writable by the target application's UID.

`stable_window_confirmed=1` is a declaration of requirement 3, not a gate
implementation. Sleep, two equal reads, or an idle-looking screen are not a
lifetime guarantee. This project cannot infer an application-specific gate.
Do not hold HybridCLR's own metadata lock across the call: the query functions
acquire it internally. Use a higher-level application loading gate instead.

Raw payload copying uses libc `memcpy` after full-range VMA checks. Original
Android top-byte allocation tags are retained for these calls. Only kernel
descriptor reads and pointer comparisons use the untagged address. This is not
PAC authentication. No process-wide SIGSEGV handler is installed: invalid
lifetime assumptions, MTE violations or concurrent unmapping can still crash
the target. The stability precondition is mandatory.

## Matching Profile

`hybridclr_dump.conf.example` contains the sample addresses/layout recovered from:

- `../HybridCLR_SO_Analysis_Guide.md`
- `../HybridCLR_Runtime_DLL_Recovery_Plan.md`
- `D:\sofixer\libil2cpp_fix.so.i64`, image base zero
- Analysis input SHA-256:
  `809544844f1dd046148ea5fcee35a0414f0256bdc995e824963ca0ff4a769da7`

The analysis input is a fixed ELF snapshot; its hash is NOT claimed to be the
runtime APK library hash. The manifest stores the runtime GNU build ID when
available, the load bias and the actual checked code hashes.

`src/profile.h` defines function names/ABI roles, the configuration schema and
token decoding rules only. No target function RVA, evidence RVA, registry RVA,
field offset or sample code fingerprint is compiled into it. Every such value
is explicitly read from the configuration file; missing entries reject the
capture instead of falling back to a built-in sample profile.

At runtime the project checks every configured API entry, the two HybridCLR
queries, and configured code that establishes raw/index layout. A mismatched
entry aborts before invoking runtime APIs. There is no ignore-fingerprint flag.
The supplied sample checks short API stubs using 16 bytes, including neighboring instructions.
Already installed instrumentation can therefore cause a deliberate rejection.

Named resolution reads the selected live ELF's `PT_DYNAMIC`, dynsym/dynstr and
SysV/GNU hash tables. It does not confuse a name string with a real export, and
does not accidentally resolve another Unity module. Missing names fall back to
the checked configuration RVA. Named functions must also be at the configured
expected address. C++ semantic names are not passed to `dlsym` as if they were
exports. `il2cpp_domain_get_assemblies` is neither resolved nor invoked, and
there is no RVA fallback or configuration key for it.

| Configuration Key | Purpose |
| --- | --- |
| `function.<name>.rva` | RVA of each required target runtime function |
| `function.<name>.fingerprint_length` | Number of entry bytes hashed |
| `function.<name>.sha256` | Required code fingerprint |
| `evidence.<name>.rva` / `.bytes_hex` | Read-only layout/code evidence, never called |
| `registry.hot.rva` | Start of the 1024-slot hot-update registry |
| `registry.aot_vector.rva` | Consecutive begin/end/capacity pointer slots |
| `layout.<name>` | Required object field offsets, including explicit zero values |

All function addresses use ELF load bias plus RVA. Heap object pointers are
already runtime addresses and are never rebased again. All configured layout
offsets are profile-specific, not a general HybridCLR or Unity ABI. Fingerprints are
guards against wrong entries, not a proof that a vendor has not modified other
code. A different build needs a newly analyzed configuration, not just new
hashes. Function signatures, 1024 hot slots and token encoding still have to
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

The linker requests 16 KiB-compatible ELF segment alignment and does not assume
4 KiB pages for its file mappings. Build using a current NDK for current Android
devices. The build commands above are instructions only; they were not run.

For application-controlled entry only, configure with
`-DHYBRIDCLR_DUMPER_AUTOSTART=OFF` to omit constructor-based startup.

## Injection Startup

1. Establish the application loading/lifetime gate described above.
2. Place `hybridclr_dump.conf.example` at the target app's
   `files/hybridclr_dump.conf`, with the appropriate settings and app-readable
   ownership/permissions.
3. Use the same external injector workflow as `PtraceIl2cppDumper`, selecting
   the target PID and loading `libhybridclr_dumper.so`. Injector command-line
   flags depend on the particular injector/version; none are invented here.
4. Resume all target threads. Keep the application gate held until completion.
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
missing RVAs/fingerprints/layouts, non-ASCII text, invalid values, or an
unconfirmed stable window are rejected.
Custom process names, isolated UIDs, and unusual app data locations should use
the exported API instead of relying on this path inference. Configuration is
loaded once per admitted capture, including exported-API captures. Editing it
after `hybridclr_dump_start` returns does not affect that capture and does not
trigger another capture automatically.

Start from the complete `hybridclr_dump.conf.example`. These are only its
execution controls, not a sufficient configuration on their own:

```ini
stable_window_confirmed=1
module_name=libil2cpp.so
initialization_timeout_seconds=30
chunk_size=262144
max_file_size=536870912
dump_pdb=1
```

Example function entries from the complete sample file:

```ini
function.GetUnderlyingInterpreterImage.rva=0x1B77D2C
function.GetUnderlyingInterpreterImage.fingerprint_length=0x74
function.GetUnderlyingInterpreterImage.sha256=6caf2c9a1e07e2b4f78ecf6f05782dbaff21234b3f1695cd449c74b2725304ab
function.FindImageByAssembly.rva=0x1B6DB68
function.FindImageByAssembly.fingerprint_length=0x64
function.FindImageByAssembly.sha256=482bed7c43dbc4aead154960417c458671eb738834798b85caea01078b4cfd5e
```

All eleven required target functions need their three entries, including
IL2CPP functions that happen to have usable exports. All three code-evidence
locations, both registry RVAs and all fourteen layout offsets are required too.
These numeric sample values are file contents, not program defaults. Integers
accept unsigned decimal or `0x`/`0X` hexadecimal. Negative values, overflow,
misalignment, incomplete hashes, unknown keys and duplicate keys are rejected.
`layout.class_image=0` is valid, but omitting it is not.

An optional `output_directory` must be absolute and writable by the target.
Otherwise the root is `<configuration parent>/hybridclr_dll_dump`, which is
`files/hybridclr_dll_dump` for the injection configuration. Each capture creates a new
`<unix-ms>-<pid>-<sequence>` subdirectory. No previous capture is overwritten.

`chunk_size` is 64 KiB through 1 MiB. `max_file_size` is at most `UINT32_MAX`,
matching the verified 32-bit raw length. Zero execution chunk/size/timeout
values in the configuration select defaults; function and registry RVAs have
no default and cannot be zero. The initialization timeout bounds waits for
the module/domain only; it does not interrupt a lock-taking native call.

## Exported API

`include/hybridclr_dumper.h` exposes C ABI version 2. Options specify the absolute
configuration file path and a caller confirmation of the stable window; output,
module, execution settings and all target function RVAs come from that file.
The previous options structure is no longer accepted.

| Function | Meaning |
| --- | --- |
| `hybridclr_dump_run(options)` | Synchronous capture in the current thread |
| `hybridclr_dump_start(options)` | Load/copy the entire configuration and launch a native worker |
| `hybridclr_dump_state()` | `IDLE`, `RUNNING`, or `FINISHED` |
| `hybridclr_dump_result()` | Last result, or `BUSY` while running |
| `hybridclr_dump_cancel()` | Request cooperative cancellation |

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
`result()`. Both the options and configuration must confirm the stable window.
Only one capture is admitted at a time. The worker attaches to
IL2CPP if necessary, and detaches only an attachment it created. An already
attached application thread is not detached by the synchronous path.

Cancellation takes effect at waits, discovery boundaries and copy blocks after
native functions return. It is not forced native-call cancellation or rollback.
Do not unload this library while any API/bootstrap/worker is active. Even
`FINISHED` is not a thread-join or SO-unload barrier; keep the library loaded.

| Result | Meaning |
| --- | --- |
| `0` | All retained inputs in the declared scope completed, subject to the caller's gate |
| `1` | Capture completed with unresolved/pending/partial/invalid entries |
| `-1` | Invalid options |
| `-2` | Another capture is running |
| `-3` | Setup, profile, runtime or I/O failure |
| `-4` | Cooperative cancellation |

## Capture Flow

1. Load and validate the complete configuration, find the selected loaded module
   using `dl_iterate_phdr`, and verify all configured code entries.
2. Obtain the domain and establish the worker's IL2CPP thread attachment.
3. Snapshot every hot registry slot and the AOT vector's valid `[begin,end)`.
4. Create a candidate for every registered object before per-image queries. Derive
   each real native assembly/image from its registry object, not a domain API.
5. Verify image/index/token/assembly associations and the nonzero native assembly
   token before calling APIs on a candidate. Pending/placeholder objects are reported.
6. Call `il2cpp_assembly_get_image` and `il2cpp_image_get_name` to check identity.
   For AOT supplementary images, actively call `FindImageByAssembly` and require
   it to return the same registry object.
7. For a hot image, obtain one real non-array class/method and actively call the
   underlying-image query. A no-method image uses the verified token/table
   fallback. Ordinary AOT images without supplementary raw are not enumerated.
8. Use the configured `layout.*` fields to read the raw object, data pointer,
   **uint32 length** and end pointer. In the supplied sample these are
   `Image+0x08`, then raw `+0x08/+0x10/+0x18`. Check
   `untag(end)-untag(data)==length` and all readable VMAs.
9. Sequentially copy `[0,length)` in bounded blocks, including original headers,
   section padding, gaps, certificates and overlays. Never substitute
   `SizeOfImage`, the last section end, or zero-filled holes for the raw length.
10. Record each block's exact file offset, written length and SHA-256. Hash the
    live raw again and recheck the raw descriptor/owning image field.
11. Independently inspect the saved PE/CLI/metadata structure and read its
    Assembly name and Module MVID. Publish successful files by rename.
12. Capture a non-null PDB object at the configured `layout.image_pdb` field
    (sample `Image+0x10`) using its independent configured raw prefix.
13. Recheck registry snapshots and associated image/assembly fields, and publish
    the report. No native or managed all-assembly enumeration API is used.

No `Execute`, `PreJit`, class constructor, business method, `LoadCLIHeader` or
other mutating parser initialization function is deliberately invoked. Class
and method metadata enumeration can still perform lazy native initialization
and allocations; the capture is not claimed to have zero side effects.

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
  rejected the format. This also preserves nonstandard/unsupported layouts.

Manifest capture statuses include `HOT_UPDATE_COMPLETE`,
`AOT_SUPPLEMENT_COMPLETE`, `PENDING_INITIALIZATION`, `PARTIAL`,
and `INVALID_FORMAT`. PDB status is independent. Every nonempty registry object
has an explicit candidate, even if it cannot safely be exported. Whole-file
SHA-256 plus MVID identifies duplicate content; `duplicate_of_capture_id` records
aliases, but separate source records/files are retained for traceability.

The manifest includes original/tag-normalized addresses, raw objects, lengths,
source routes, representative methods, registry indices, code bindings, block
hashes, whole hashes, names/MVIDs, configuration path/text SHA-256 and capture
failures. It explicitly sets `all_process_assemblies_enumerated=false` and
`ordinary_aot_without_raw_enumerated=false`; unknown ordinary AOT assemblies
are not counted as successfully checked or excluded.
`complete_within_declared_scope` is false for unresolved registry objects,
changed snapshots, incomplete DLLs, or requested PDB failures. Equal snapshots
and hashes are change detectors, never replacements for the external gate.

Structural inspection supports standard PE32/PE32+, CLI metadata streams,
standard 0..44 metadata table layouts and Portable PDB root/#Pdb identification.
It deliberately rejects unknown streams, unsupported/extended metadata layouts,
overlapping ranges and invalid indices. It does not verify every IL instruction,
method body, EH clause, signature semantic, resource payload or complete PDB
debug table. Use an independent managed-file analysis tool for those checks.

## Source Map

| File | Responsibility |
| --- | --- |
| `src/entry.cpp` | Injection bootstrap, configuration and versioned exported API |
| `src/config.cpp` | Shared strict configuration loading, mandatory values and source hash |
| `src/profile.h` | Function/ABI roles and configuration schema, no sample addresses |
| `src/platform.cpp` | In-process ELF resolution, readable ranges and descriptor I/O |
| `src/dumper.cpp` | Active runtime queries, registry audit, copying and JSON manifest |
| `src/pe.cpp` | Bounded independent PE/CLI/metadata inspection and identity |
| `src/sha256.cpp` | Streaming SHA-256 without external crypto dependencies |

The project borrows the injected-worker architecture of the local example, not
its memory-snapshot/text-dump implementation or NativeBridge code. The existing
example, HybridCLR checkout, original documents and IDA database are unchanged.
