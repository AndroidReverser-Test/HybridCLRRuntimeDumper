# Android Device Validation

## Result

On 2026-10-05 the corrected project was cross-built, injected and exercised in
`com.plantsvszombies3.mengxing`. The final capture recovered **25/25 registered
retained DLL inputs**, totaling **26,188,800 bytes**: four hot-update DLLs and 21
supplementary AOT DLLs. All final files passed independent host verification.
The app's PID remained 12005 after capture and subsequent verification; no native
crash was observed. This is not a gameplay/functionality test.

The user explicitly authorized an experimental run without an application-side
loading/lifetime gate. The configuration therefore truthfully used:

```ini
stable_window_confirmed=0
allow_ungated_capture=1
```

The final manifest reports `all_registered_inputs_exported=true`,
`registry_snapshots_unchanged=true`, `experimental_ungated_capture=true`,
`complete_within_declared_scope=false`, and `result_code=1`. Result 1 is expected
for this mode, not a DLL-copy failure. A coherent stable runtime snapshot is not
certified. Ordinary AOT original DLLs without retained supplementary raw data,
unloaded/history files and files not yet loaded remain outside the scope.

## Environment And Artifacts

| Item | Value |
| --- | --- |
| Device serial | `LVLNINYXKR4L6HAE` |
| Device | Xiaomi 22041211AC, rubens, ARM64, Android API 31 |
| App | `com.plantsvszombies3.mengxing`, version 11.0.0, versionCode 1207 |
| App UID | 10254 |
| Unity | 2022.3.30f1c1, IL2CPP, arm64-v8a, stripping enabled |
| NDK / compiler | 27.0.12077973 / Clang 18.0.1 |
| CMake | 3.22.1, Ninja |
| Build | Release, Android API 29, static libc++, 16 KiB LOAD alignment |
| Target runtime GNU build ID | `b1ab380823c8af07794776c401e3a6ca57de9441` |
| Final runtime load bias | `0x7aa6a73000` |
| Final dumper SO SHA-256 | `a2e0bfe8336b883e4ada471c9565a47ecfef35a951304653f5d9827518a0fe94` |
| Final SO | `build/arm64/libhybridclr_dumper.so` |
| Device SO | `/data/local/tmp/libhybridclr_dumper.so` |
| Device config | `/data/user/0/com.plantsvszombies3.mengxing/files/hybridclr_dump.conf` |
| First capture | `1791178476665-10483-0` |
| Final capture | `1791179923565-12005-0` |

Project-relative artifact paths:

```text
build/captures/1791178476665-10483-0/       first run, original format rejection evidence
build/captures/1791179923565-12005-0/      final DLLs, manifest.json, logcat.txt, module.sha256
build/first-capture-verification.json     expected first-run host FAIL
build/invalid-format-diagnosis.json       independent diagnosis of all 21 AOT inputs
build/final-capture-verification.json    final host PASS
build/cross-run-verification.json        full-byte comparison and aggregate checks
```

The final app-private directory is:

```text
/data/user/0/com.plantsvszombies3.mengxing/files/hybridclr_dll_dump/1791179923565-12005-0
```

An adb-readable staging copy is under
`/data/local/tmp/hybridclr-verification/1791179923565-12005-0`.

The dumper hash identifies the injected artifact, not the target `libil2cpp.so`.
The analysis IDB's fixed-ELF hash is likewise not an APK-library hash.

## Defects Found And Corrected

1. The initial build failed because Android NDK ELF headers do not define
   `ELF64_ST_VISIBILITY`. `Module::match_symbol` now extracts the two visibility
   bits directly, preserving the existing default/protected export check.
2. The initial capture successfully copied all raw bytes but misclassified all
   21 supplementary AOT DLLs as `INVALID_FORMAT`. Their Cecil tables headers use
   Reserved2 `0x0a`, not `0x01`; this byte does not alter the stored row layout.
3. The same files use Sorted mask `0x00c416003301fa00`, including inactive bits
   50, 54 and 55. The inspector now applies its supported-table mask only to
   Valid, which actually describes the tables stored in the stream. It still
   rejects active tables above 44 and retains all row, heap and range checks.

Example: DOTween's tables header starts at file offset `0x12000`, has Valid mask
`0x00001e092bb69f57`, and parses independently as assembly `DOTween`, MVID
`ca2b168c-e2fc-4396-b47a-a507b92da451`.

The experimental opt-in was added with the user's approval, rather than claiming
that an idle app or matching reads constitute a real lifetime gate. It defaults
off; missing opt-in with `stable_window_confirmed=0` is still rejected.

## Runtime And Host Checks

- Nine IL2CPP functions resolved from the selected live ELF's real dynamic
  symbols at their expected addresses. Both HybridCLR queries used checked RVAs.
- All 11 live function fingerprints matched the configuration; all three layout
  code-evidence locations also passed their exact-byte checks.
- All four hot images used a real representative MethodInfo and actively called
  `GetUnderlyingInterpreterImage`; none needed token-only fallback.
- All 21 AOT images actively called `FindImageByAssembly` and matched their
  registered object. All 25 assembly/image associations passed.
- Every output's declared length, written length, full block coverage and copy
  SHA-256 matched the second live hash pass and independently read host file.
- Independent parsers checked 21,698 TypeDef and 174,494 MethodDef rows,
  165,802/165,802 RVA-bearing IL bodies, 3,074,851 decoded instructions, 4,746 EH
  sections, 6,026 EH clauses, and seven embedded resource ranges.
- All 116 chunks passed host coverage and SHA-256 checks. All 25 final DLLs are
  byte-for-byte identical to the first cold-start capture, including its AOT
  `.invalid.bin` files. No files or manifests were rewritten to simulate success.
- All 25 PDB fields were null/`NOT_PRESENT`; actual PDB capture was not exercised.
- The optional native device checks returned `PASS 15 FAIL 0`, including valid
  Cecil/standard headers, inactive Sorted bits, rejection of active table 45,
  bad headers/truncation, and strict configuration opt-in/rejection.

Host PASS concerns the listed files, not independently replayed runtime queries.
IL checks cover decoding and boundaries, not stack/type safety, signatures or
behavioral semantics. Resource checks cover bounds, not payload semantics.
Equal hashes and two cold-start captures do not replace the missing lifetime
gate or demonstrate the original pre-stripping/published DLL identity.

The app emitted missing-script/resource and TMPro managed errors before the
final injection. They were not introduced by the capture and were not repaired
as part of this validation. `JNI_OnLoad not found` in the injector is expected:
this library starts via its native constructor, not JNI.

## Reproduction

Run from this project directory. Substitute the device root key locally;
credentials are not stored in these scripts. Do not reinject an updated SO into
a process still holding the earlier module and assume its constructor ran again;
the verified second run used a fresh app process, without clearing app data.

```powershell
$cmake = "D:/androidSDK/cmake/3.22.1/bin/cmake.exe"
& $cmake -S . -B build/arm64 -G Ninja "-DCMAKE_MAKE_PROGRAM=D:/androidSDK/cmake/3.22.1/bin/ninja.exe" "-DCMAKE_TOOLCHAIN_FILE=D:/androidSDK/ndk/27.0.12077973/build/cmake/android.toolchain.cmake" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29 -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release -DHYBRIDCLR_DUMPER_BUILD_TESTS=ON
& $cmake --build build/arm64
adb -s LVLNINYXKR4L6HAE push build/arm64/libhybridclr_dumper.so /data/local/tmp/libhybridclr_dumper.so
adb -s LVLNINYXKR4L6HAE push verification/device.conf /data/local/tmp/hybridclr_dump.conf
adb -s LVLNINYXKR4L6HAE push verification/prepare_device.sh /data/local/tmp/prepare_hybridclr_dump.sh
adb -s LVLNINYXKR4L6HAE shell "/data/local/tmp/kpatch <root-key> su -c 'sh /data/local/tmp/prepare_hybridclr_dump.sh'"
adb -s LVLNINYXKR4L6HAE shell am start -W -n com.plantsvszombies3.mengxing/com.unity3d.player.base.StartUpActivity
```

Wait for application DLL loading to complete before injection. This is only
initialization timing, not a synchronization guarantee.

```powershell
adb -s LVLNINYXKR4L6HAE shell "/data/local/tmp/kpatch <root-key> su -c '/data/local/tmp/AndKittyInjector -pkg com.plantsvszombies3.mengxing -lib /data/local/tmp/libhybridclr_dumper.so -dl_memfd'"
adb -s LVLNINYXKR4L6HAE logcat -d -s HybridCLRDump:I
```

After the completion log supplies the new session name, export it:

```powershell
adb -s LVLNINYXKR4L6HAE push verification/export_capture.sh /data/local/tmp/export_hybridclr_capture.sh
adb -s LVLNINYXKR4L6HAE shell "/data/local/tmp/kpatch <root-key> su -c 'sh /data/local/tmp/export_hybridclr_capture.sh <session>'"
adb -s LVLNINYXKR4L6HAE pull /data/local/tmp/hybridclr-verification/<session> build/captures/<session>
python -m venv build/verify-env
& ./build/verify-env/Scripts/python.exe -m pip install -r verification/requirements.txt
& ./build/verify-env/Scripts/python.exe verification/verify_captures.py build/captures/<session> --output build/final-capture-verification.json
```

The host verifier returns zero for per-file PASS even though the ungated native
capture intentionally returns 1. It does not load or execute the DLLs.

Optional native regression invocation, using the already retained first fixture:

```powershell
adb -s LVLNINYXKR4L6HAE push build/arm64/hybridclr_native_checks /data/local/tmp/hybridclr_native_checks
adb -s LVLNINYXKR4L6HAE shell "/data/local/tmp/kpatch <root-key> su -c 'chmod 755 /data/local/tmp/hybridclr_native_checks'"
adb -s LVLNINYXKR4L6HAE shell "/data/local/tmp/kpatch <root-key> su -c '/data/local/tmp/hybridclr_native_checks /data/local/tmp/hybridclr_dump.conf /data/local/tmp/hybridclr-verification/1791178476665-10483-0/aot_5_DOTween.dll.invalid.bin 0x12000'"
```
