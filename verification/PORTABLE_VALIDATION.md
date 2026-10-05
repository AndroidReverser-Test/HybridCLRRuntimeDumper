# Semantic Discovery Validation

Validation date: 2026-10-05. All device operations used the authorized test
application `com.plantsvszombies3.mengxing`. No APK, original HybridCLR source,
analysis plan, IDA database or application data was patched. Application processes
were restarted without `pm clear`. Existing configurations were backed up by the
deployment script. Device root credentials are intentionally not recorded here.

## Build And Identity

| Item | Observed Value |
| --- | --- |
| Device | `LVLNINYXKR4L6HAE`, Android API 31, ARM64 |
| Application | `com.plantsvszombies3.mengxing`, version 11.0.0 / versionCode 1207 |
| Target GNU build ID | `b1ab380823c8af07794776c401e3a6ca57de9441` |
| NDK / CMake | `27.0.12077973` / `3.22.1` |
| Build | Release, `arm64-v8a`, Android API 29, `c++_static` |
| Options | `HYBRIDCLR_DUMPER_AUTOSTART=ON`, `HYBRIDCLR_DUMPER_BUILD_TESTS=ON` |
| Output | `build/portable-arm64/libhybridclr_dumper.so` |
| Dumper SHA-256 | `249e5f09b8b1127c6e320b9352d80fcf76d28076bd703e2724961f7d009cfdec` |
| Auto configuration SHA-256 | `4dfeafb35abcdaedc06074c1a2ca96f371b86bee354ad2f238ed264095b3e159` |
| Profile configuration SHA-256 | `91aeacc53743a06b3a20d2df6fb6e1dd7579660adeaf7960709acfc10bd4e826` |

`llvm-readelf` confirmed little-endian ELF64 / AArch64 / DYN and LOAD alignment
`0x4000`. `llvm-nm --dynamic --defined-only` reported exactly five defined
exports, the `hybridclr_dump_*` C API. Static C++ archive symbols are hidden using
`--exclude-libs,ALL`. The dumper hash above matched the device staging hash in
every exported session. It is not the target runtime's ELF hash.

## Discovery Changes

The recommended `discovery_mode=auto` uses seven real dynamic exports:

```text
il2cpp_domain_get
il2cpp_assembly_get_image
il2cpp_image_get_name
il2cpp_thread_current
il2cpp_thread_attach
il2cpp_thread_detach
il2cpp_resolve_icall
```

The worker attaches normally, resolves the registered
`HybridCLR.RuntimeApi::PreJitClass(System.Type)` icall, and reads its code. It does
not invoke PreJitClass, the AOT lookup helper, the raw loader or business methods.
No class or MethodInfo enumeration occurs in auto mode.

Bounded semantic analysis derives the registries, image token/owner fields, AOT
target field, public identity getters and raw loader's pointer64/uint32/pointer64
stores. Registered object prefixes are inspected for unique, cross-checked
native image and raw owners. No whole-heap scan is performed.

The following values were discovered in both live auto sessions, not supplied
by configuration or compiled as target-specific constants:

| Result | Value |
| --- | --- |
| Hot registry RVA | `0x42A4468` |
| AOT vector RVA | `0x42A4450` |
| Image token / assembly | `0x40` / `0x10` |
| Assembly image / image name | `0x0` / `0x0` |
| AOT target assembly | `0xF8` |
| Hot native image owner field | `0x100` |
| DLL raw owner field | `0x08` |
| Raw data / uint32 length / end | `0x08` / `0x10` / `0x18` |

The supplied old profile continues to work without adding a new required key.
Its formerly implicit `Assembly+0` image pointer is now an optional
`layout.assembly_image` field, defaulting to zero for deployed profiles.

Payloads in both modes are read through failure-reporting self
`process_vm_readv` / `/proc/self/mem`, not directly dereferenced by memcpy.
Stale mapping failure is tested. This reduces a fault source but supplies no
lifetime pin or atomic snapshot guarantee.

## Device Sessions

All three new sessions used the same final dumper artifact and emitted schema 3.
Each exported 25 complete DLLs: four hot-update and 21 supplementary AOT inputs.
Each contains 26,188,800 DLL bytes, 116 coverage chunks, and matching copy/live
SHA-256 values. Host checks independently passed 165,802 IL method bodies and
6,026 EH clauses per session.

| Session | Mode | PID | Runtime Load Bias | Host / Actual-Byte Comparison |
| --- | --- | --- | --- | --- |
| `1791196054447-17919-0` | auto | 17919 | `0x7AA0429000` | PASS; 25/25 match historical `1791179923565-12005-0` |
| `1791203411317-27900-0` | profile regression | 27900 | `0x7AA750F000` | PASS; 25/25 match first auto session |
| `1791203675884-28745-0` | auto repeat | 28745 | `0x7AA3E06000` | PASS; 25/25 match profile regression |

Every auto candidate recorded `SEMANTIC_REGISTRY_PUBLIC_API`,
`private_query_status=NOT_REQUESTED`, a null representative MethodInfo, and true
public-query/association/native-name checks. Semantic code/GOT/vptr/vtable
evidence and registry snapshots were unchanged on final audit. Auto configuration
contains no function RVA, expected code hash, registry address or field offset.

The profile regression matched all eleven configured function fingerprints and
three layout-evidence ranges. Its four hot objects used real MethodInfo queries;
its 21 AOT objects used the configured private AOT query. No no-method fallback
was used. `semantic_evidence_unchanged=false` in this mode means that the optional
auto semantic audit was not performed, not that profile fingerprints failed.

Auto PDB collection was explicitly disabled. The profile regression reported
`NOT_PRESENT` for all 25 known PDB fields. Actual nonempty PDB export was not
tested. Auto cannot certify PDB absence; requesting it without a positively
identified object yields `NOT_DISCOVERED` and an incomplete capture.

The apps were alive at each post-capture check. The final PID was `28745`; the
crash buffer was empty at the final check. These are observations, not a promise
about subsequent application behavior.

All sessions were explicitly ungated experiments. They correctly recorded:

```json
{
  "stable_window_confirmed_by_caller": false,
  "experimental_ungated_capture": true,
  "registry_snapshots_unchanged": true,
  "all_registered_inputs_exported": true,
  "complete_within_declared_scope": false,
  "result_code": 1
}
```

Strict gated capture was not dynamically validated and is not simulated by
changing a configuration flag. Matching reads and hashes cannot prove a gate.

## Regression Checks

| Check | Result |
| --- | --- |
| `hybridclr_discovery_checks` | PASS 98 / FAIL 0 |
| `hybridclr_native_checks` | PASS 31 / FAIL 0 |
| `hybridclr_dumper_checks` | PASS 36 / FAIL 0 |
| `python -B -m unittest verification.test_verify_manifest -v` | 43 tests PASS |
| Total | 208 checks/tests passed |
| Python dependency consistency | `pip check`: no broken requirements |
| Final build / whitespace | Ninja: no work to do; `git diff --check`: clean |

Discovery tests cover relocation, register and field variations, GOT/direct
addresses, B thunks, supported helper calls, bounded graph rejection, ambiguous
results, getter provenance and raw store widths. Negative cases include STP's
second source, unreachable constant LSR/AND/BIC/ADD branches, unsupported code,
changed evidence, failed reads and exhausted budgets. An earlier parser build
also passed UBSan-trap and offline same-sample ELF checks; those earlier checks
are not claimed as sanitizer coverage of the final full dumper.

Dumper checks use an independently mapped fixture SO and fake public APIs, not
the application runtime. They verify that a copy-size limit cannot hide a second
raw owner, bad P/N/E or unknown raw format cannot manufacture unique ownership,
over-limit copies remain partial, private queries remain unused in auto mode,
public identity disagreement is rejected, and cancelled audits do not publish an
unperformed success assertion. There is no scheduler-dependent cancellation test.

Manifest tests cover historical schema 2, schema 3 route/evidence consistency,
actual native/metadata identity checks, PDB absence distinctions, comparison
multisets, changed reference bytes, missing inputs and safe output paths.

Commands actually used, after deploying the executable files and raw fixture:

```powershell
adb -s LVLNINYXKR4L6HAE shell /data/local/tmp/hybridclr_discovery_checks
adb -s LVLNINYXKR4L6HAE shell "/data/local/tmp/hybridclr_native_checks /data/local/tmp/hybridclr_test.conf /data/local/tmp/hybridclr_test_DOTween.dll 0x12000"
adb -s LVLNINYXKR4L6HAE shell "LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/hybridclr_dumper_checks /data/local/tmp"
& "./build/verify-env/Scripts/python.exe" -B -m unittest verification.test_verify_manifest -v
```

The native configuration test uses `verification/device.conf` and the same
historical DOTween fixture, whose tables-header file offset is `0x12000`.

## Artifacts And Reverification

Each new session is preserved under `build/captures/<session>/` with DLLs,
`manifest.json`, `logcat.txt`, `module.sha256` and `host-verification.json`.
No earlier session was overwritten. Final device configuration is the recommended
ungated `verification/auto-device.conf`, installed in the application's files
directory; previous private configurations remain as deployment-script backups.

From the project directory, the final actual-byte comparison can be repeated:

```powershell
& "./build/verify-env/Scripts/python.exe" -B verification/verify_captures.py build/captures/1791203675884-28745-0 --compare-with build/captures/1791203411317-27900-0 --output build/captures/1791203675884-28745-0/host-verification.json
```

`--compare-with` rereads actual files on both sides, checks declared lengths and
both hashes, and parses Assembly name/MVID. It compares a multiset including kind,
identity, length and content hash, not IDs, ordering or filenames. It does not
repeat reference IL/EH validation or replay runtime queries. A mismatched or
missing reference artifact makes the report fail and returns exit code 1.

## Compatibility Boundary

These device sessions exercise one target runtime binary under different ASLR
bases, not different real HybridCLR versions. Synthetic variations and same-sample
IDA/offline analysis are supporting evidence only. Auto does not establish the
precise HybridCLR patch version.

The supported shape still requires metadata-v2 masks/shift 22, 1024 hot pointer
slots, a three-pointer AOT vector, an Itanium vptr at zero, and recognized bounded
ARM64 getter/loader/control-flow semantics. PAC/PLT/indirect entry thunks, different
containers or raw layouts that cannot be proved are rejected. There is no silent
fallback to sample RVAs. Unknown builds must be separately validated or use a
reviewed explicit profile.

Ordinary AOT assemblies without retained supplementary raw, unloaded history,
files never loaded, freed failed inputs and pre-stripping originals remain
unrecoverable by this route. "All DLLs" refers only to the declared current
retained-input registry union. The deployment scripts still have sample-specific
package/user/output paths.
