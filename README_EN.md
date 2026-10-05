# HybridCLRRuntimeDumper

[中文](README.md) | **English**

An Android ARM64 in-process dumper that actively calls IL2CPP/HybridCLR APIs and reads retained raw data to export .NET DLLs in their original file layout, plus optional Portable PDBs.

The output library, `libhybridclr_dumper.so`, supports explicit application calls and automatic startup after external injection. It does not include an injector, install loading hooks, scan the whole heap, or reconstruct DLLs from native code or interpreter IR. Use only with applications you own or are authorized to inspect.

## Recoverable Scope

- Currently registered hot-update DLLs whose complete raw copies survive.
- Currently registered supplementary AOT DLLs, including SUPERSET inputs.
- Identifiable Portable PDBs with retained raw copies, saved separately.

"All" means only the union of these retained inputs, **not every assembly in the process**. Ordinary AOT DLLs without supplementary raw data, files not yet loaded or already unloaded, freed inputs, and changes that exist only in IR are outside the recovery scope.

## How It Works

1. Read the configuration, wait for the target module and IL2CPP domain, and attach the current thread to IL2CPP if necessary.
2. Locate the hot-update and supplementary AOT registries, create candidates, and confirm object identity through runtime APIs.
3. Locate retained raw objects, read their full file lengths in blocks, and check two SHA-256 passes, descriptors, and the saved PE/CLI metadata.
4. Recheck registries, associations, and discovery evidence, then publish files and `manifest.json`.

Explicitly selecting `discovery_mode=auto` is recommended. Bounded A64 semantic analysis locates registries and fields without configured RVAs, expected code hashes, or object offsets. It resolves the entry address of `HybridCLR.RuntimeApi::PreJitClass(System.Type)` and reads its code; **it does not execute PreJitClass, discovered parsers, or business methods**.

Auto requires these seven real dynamic exports from the selected module:

```text
il2cpp_domain_get
il2cpp_assembly_get_image
il2cpp_image_get_name
il2cpp_thread_current
il2cpp_thread_attach
il2cpp_thread_detach
il2cpp_resolve_icall
```

Auto supports only the recognized metadata-v2 ABI, including shift-22 token decoding, 1024 hot slots, a three-pointer AOT vector, and the Itanium vptr-at-zero layout. Unknown code, ambiguity, PAC, and unsupported containers are rejected. There is no automatic profile fallback, and **this is not arbitrary-version HybridCLR support**.

`discovery_mode=profile` is a manual alternative. It requires target-build analysis of all function RVAs, code fingerprints, registries, and layouts, then actively invokes verified private HybridCLR queries. See the [profile configuration example](hybridclr_dump.conf.example); its sample values are not reusable across arbitrary builds. Omitting `discovery_mode` selects `profile`, not auto. Auto rejects `function.*`, `registry.*`, `layout.*`, `evidence.*`, and `profile.analysis_sha256` inputs.

## Build

Requires the Android NDK, CMake 3.22+, and Ninja. Only Android `arm64-v8a` is supported. No APK, Gradle, Java, or HybridCLR source build is required.

Run these PowerShell commands from the project root after setting `ANDROID_NDK_HOME` and adding `cmake` and `ninja` to `PATH`:

```powershell
$ndk = $env:ANDROID_NDK_HOME
cmake -S . -B build/arm64 -G Ninja `
    "-DCMAKE_TOOLCHAIN_FILE=$ndk/build/cmake/android.toolchain.cmake" `
    -DANDROID_ABI=arm64-v8a `
    -DANDROID_PLATFORM=android-29 `
    -DANDROID_STL=c++_static `
    -DCMAKE_BUILD_TYPE=Release `
    -DHYBRIDCLR_DUMPER_AUTOSTART=OFF
if ($LASTEXITCODE -eq 0) { cmake --build build/arm64 }
```

Output: `build/arm64/libhybridclr_dumper.so`. This example selects explicit API calls. For automatic capture after injection, change `HYBRIDCLR_DUMPER_AUTOSTART` to `ON`, reconfigure, and rebuild. The project default is `ON`; do not use the `OFF` build above when expecting injection alone to start a capture.

## Configuration And Synchronization

The target application's UID must be able to read the configuration and write to the output directory. Start strict auto captures from [hybridclr_dump.auto.conf.example](hybridclr_dump.auto.conf.example):

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

**Use this configuration only while a real application loading/lifetime gate is held.** The gate must prevent relevant loads, raw destruction, and modification throughout discovery, copying, and audit. Confirmation flags implement no synchronization. Do not hold HybridCLR's own metadata lock across the capture call; runtime APIs may acquire it internally.

For an authorized experiment without a gate, use [verification/auto-device.conf](verification/auto-device.conf), replacing the two synchronization settings above with:

```ini
stable_window_confirmed=0
allow_ungated_capture=1
```

An ungated capture never returns complete success, even if every file passes. Equal hashes, registry snapshots, or an idle screen do not replace lifetime protection. Raw reads use self `process_vm_readv`, with `/proc/self/mem` as a fallback; failed or short reads are not zero-filled. These checks do not guarantee an atomic snapshot or eliminate crashes caused by invalid runtime calls.

| Setting | Meaning |
| --- | --- |
| `module_name` | Target module basename; default `libil2cpp.so` |
| `initialization_timeout_seconds` | Default 30 seconds; bounds module/domain/auto-icall readiness waits, not the whole capture or a native call |
| `chunk_size` | Default 256 KiB; nonzero values must be 64 KiB through 1 MiB |
| `max_file_size` | Default 512 MiB, at most `UINT32_MAX`; limits copying, not auto raw-owner selection |
| `dump_pdb` | Explicitly disabled above; the program default when omitted is enabled. Auto reports `NOT_DISCOVERED` and an incomplete request if no unique PDB is found; this does not certify absence |
| `output_directory` | Optional absolute path; defaults to `<configuration parent>/hybridclr_dll_dump` |

Configuration uses ASCII `key=value` text with `#` comments. Do not add non-ASCII comments or a BOM. Unknown keys, duplicate keys, invalid values, and mixed discovery modes are rejected. Each call loads the configuration once; editing it neither changes an admitted capture nor starts another one automatically.

## Usage

### Explicit Application Calls

With autostart disabled, an application native component can link the library or load it and resolve its exports. Use C ABI v2 from [include/hybridclr_dumper.h](include/hybridclr_dumper.h). After the relevant DLLs have loaded, a real gate is held, and the configuration declares `stable_window_confirmed=1`, call synchronously:

```cpp
#include "hybridclr_dumper.h"

// The application's loading/lifetime gate is already held.
HybridClrDumpOptions options{};
options.struct_size = sizeof(options);
options.abi_version = HYBRIDCLR_DUMPER_ABI_VERSION;
options.config_path = "/data/user/0/com.example.test/files/hybridclr_dump.conf";
options.stable_window_confirmed = 1;
int result = hybridclr_dump_run(&options);
// Release the gate only after the synchronous call returns.
```

`config_path` must be absolute. Options select the configuration and additionally confirm the stable window; they do not override its output directory, discovery mode, or synchronization declaration. For ungated experiments, use the experimental configuration and set the options confirmation to `0`.

| API | Purpose |
| --- | --- |
| `hybridclr_dump_run(options)` | Synchronous capture in the current thread; returns the final result |
| `hybridclr_dump_start(options)` | Reads and copies the configuration, then starts a native worker; `0` means accepted only |
| `hybridclr_dump_state()` | Reports `IDLE`, `RUNNING`, or `FINISHED` |
| `hybridclr_dump_result()` | Reports the last result, or `BUSY` while running |
| `hybridclr_dump_cancel()` | Requests cooperative cancellation; does not forcibly interrupt native calls |

Only one capture is admitted at a time; another can be requested after completion. For asynchronous captures, keep the gate held until the state is `HYBRIDCLR_DUMP_FINISHED`, then read the result. The library manages thread attachment and detaches only an attachment it created. **Keep the SO loaded; `FINISHED` is not a safe `dlclose` barrier.**

### Automatic Startup After Injection

1. Build with `HYBRIDCLR_DUMPER_AUTOSTART=ON` and select either a strict gated configuration or an explicit ungated experimental configuration.
2. Install it as `/data/user/<user>/<package>/files/hybridclr_dump.conf`, readable by the application. Default output is under the same `files` directory.
3. Wait for the application's relevant DLLs to load, then use an external injector to load the SO into the target PID. This project does not supply injector commands.
4. Resume target threads promptly; do not leave a runtime-lock holder suspended. For strict captures, retain the application gate until completion.
5. Use `adb logcat -s HybridCLRDump` to find completion logs and the session path, then export the entire session directory.

The constructor only creates a bootstrap thread, which infers the configuration path from the process package name and Android user. For user 0, a missing primary path falls back to `/data/data/<package>/files/hybridclr_dump.conf`. Missing configuration starts no capture. There is no `JNI_OnLoad`. Custom process names, isolated UIDs, and nonstandard data paths should use the explicit API.

Autostart attempts once and does not watch configuration changes. Reloading the same SO does not guarantee another constructor invocation. For repeat captures, use the API or, when interrupting test state is acceptable, restart the target process and inject again.

## Output And Results

Each capture creates a separate `<unix-ms>-<pid>-<sequence>` directory without overwriting earlier output:

```text
hybridclr_dll_dump/<session>/
    manifest.json
    hot_1_HotUpdate.dll
    aot_2_System.Core.dll
    hot_1_HotUpdate.pdb
```

Names and counts are illustrative. `.dll` / `.pdb` files passed full copying and supported structural checks; `.partial` files indicate unfinished copying or rechecks, while `.invalid.bin` files contain complete bytes rejected by structural inspection. Early rejection may produce no file. **File existence does not mean the capture succeeded**; check associations and the final audit too. Duplicate content is identified by SHA-256 and MVID through `duplicate_of_capture_id`; separate source records and files are retained.

`manifest.json` uses schema 3 and records sources, identities, lengths, block/whole-file hashes, discovery evidence, and failures. Key fields:

- `all_registered_inputs_exported`: a summary of export and association checks for registered inputs and requested PDBs, not standalone proof of final success.
- `semantic_evidence_unchanged`: whether auto's final semantic evidence audit passed.
- `experimental_ungated_capture`: whether the capture lacks a declared real gate.
- `complete_within_declared_scope`: whether the declared scope is complete; always `false` for ungated captures.

Also check `result_code`, `cancelled`, and individual candidate statuses. Cancellation or an exception during the final audit may leave an earlier export summary flag set to `true`.

| Native Result | Meaning |
| --- | --- |
| `0` | Declared scope completed; a real gate remains the caller's precondition |
| `1` | Unfinished/invalid candidates or files, or an ungated experiment |
| `-1` | Options or configuration loading/validation failed |
| `-2` | Another capture is running |
| `-3` | Global setup, discovery, runtime, or report-output failure |
| `-4` | Cooperative cancellation |

## Independent Verification

After pulling the entire session to the host, install verification dependencies with Python 3 and run:

```powershell
python -m pip install -r verification/requirements.txt
python verification/verify_captures.py "<local-session-directory>" `
    --output "<local-session-directory>/host-verification.json"
```

The verifier checks actual lengths, block coverage, hashes, Assembly/MVID identity, IL/EH boundaries, and resource bounds without executing managed code. Exit code `0` means `PASS`, `1` means verification or comparison failed, and `2` means a current-session input, dependency, or output error. Add `--compare-with "<reference-session-directory>"` to compare actual DLL bytes, metadata identities, and duplicate multiplicity, not PDBs. Missing or invalid reference sessions also return `1` as comparison failures. Host `PASS` does not prove a real gate, replay live discovery, or certify cross-version compatibility.

Build optional native regression checks with `-DHYBRIDCLR_DUMPER_BUILD_TESTS=ON`. Deployment details and historical device evidence are linked below; historical sample counts are not success criteria for a new target:

- [Complete Workflow (Chinese)](DLL_Dump_Workflow_CN.md): detailed build, injection, and export steps. Device helper scripts hardcode the sample package, user 0, and default paths; adapt them before use elsewhere.
- [Semantic Discovery Validation](verification/PORTABLE_VALIDATION.md): auto and profile regression evidence. Recorded coverage is one target build, not validation across real framework versions.
- [Historical Profile Validation](verification/DEVICE_VALIDATION.md): earlier profile device sessions.
