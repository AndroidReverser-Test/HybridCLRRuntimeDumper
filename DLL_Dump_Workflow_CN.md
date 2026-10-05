# HybridCLRRuntimeDumper DLL 导出完整工作流

本文说明如何从源码构建 `libhybridclr_dumper.so`，通过 adb 和 AndKittyInjector 将其注入 Android 应用，以公开 IL2CPP 接口和有界 HybridCLR 语义发现导出 DLL，最后将结果拉回电脑进行独立校验。主流程推荐显式使用 `discovery_mode=auto`，手工 `profile` 仅作为经分析确认后的显式备选。

新 `auto` 已在 `com.plantsvszombies3.mengxing` 当前 binary 上实际注入并通过独立 host 校验，session 为 `1791196054447-17919-0`。这只是同一个目标构建的实机验证，**跨不同真实 HybridCLR 框架版本仍未验证**。新结果摘要见第 14.4 节，[PORTABLE_VALIDATION.md](verification/PORTABLE_VALIDATION.md) 用于汇总具体证据和后续回归；旧 profile 历史记录单独保留于第 14.5 节，不能当作 auto 证据。电脑端命令使用 Windows PowerShell 5.1，设备端命令通过 `adb shell` 执行。除可选的应用集成章节外，不需要修改 APK、构建 HybridCLR 源码或添加 Java 代码。

仅用于自己拥有或已获授权分析的应用。

## 1. 先明确导出的范围

这里的“全部 DLL”是指：**采集时两份 HybridCLR 注册表中，仍保留完整 raw 文件副本的热更 DLL 和 AOT 补充 DLL 的并集**，不是应用历史上或发布前的全部原始程序集。

| 对象 | 是否能通过当前项目恢复 |
| --- | --- |
| 当前已注册、raw 副本仍存在的热更 DLL | 可以 |
| 当前已注册的 AOT 补充 DLL，包括 SUPERSET 输入 | 可以 |
| 存在独立 raw 对象的 Portable PDB | 可单独导出，不能拼入 DLL；auto 必须正向发现对象，不能认证不存在 |
| 没有补充 raw 数据的普通 AOT 原始 DLL | 不可以 |
| 尚未加载的文件、已卸载的历史版本、失败后已经释放的输入 | 不可以 |
| AOT 裁剪前的原始 DLL、上游密文或压缩封包 | 不保证恢复 |
| 只发生在解释器 IR 中、没有写回 raw 的修改 | 不会自动体现在导出的 DLL 中 |

项目导出的是运行时保留的原文件布局字节。它不会用 native 机器码反推完整 IL，也不会把反射结果重新拼装为另一份 PE 文件。

本次新 auto 实机 session 导出 4 个热更 DLL 和 21 个 AOT 补充 DLL，共 25 个；旧 profile 历史样本也有相同计数，但属于不同证据记录。这个计数不是其他版本或其他采集时点的固定预期。

## 2. 项目如何工作

主要工作流如下：

```text
构建 Android ARM64 SO
    -> 用 adb 放入 /data/local/tmp
    -> 将 auto 配置安装到应用的 files 目录，不输入目标 RVA / 哈希 / 字段偏移
    -> 启动应用并完成相关 DLL 加载
    -> AndKittyInjector 开始通过 memfd 加载 SO
    -> 加载期间，SO 构造函数创建 native 工作线程；注入器随后恢复目标线程
    -> 读取配置，定位 libil2cpp.so，解析七个真实动态导出
    -> 获取 domain，必要时 attach 到 IL2CPP
    -> resolve_icall 只取 PreJitClass 入口，不执行它；有界读取 A64 CFG 和 getter 指令
    -> 读取热更固定表与 AOT vector，建立候选对象集合
    -> 互校 token / owner / getter，再调用公开接口确认 assembly / image 身份
    -> 在对象前缀内唯一定位 raw，读取 vtable load prefix 推导 data64 / length32 / end64
    -> 校验 P/N/E、可读范围和 PE magic，按原文件 offset 分块 kernel-read 完整 [0, length)
    -> 再次计算 live raw 哈希，检查描述符、注册表和实际语义证据
    -> 发布 DLL / PDB 和 manifest.json
    -> 通过 root 将结果复制到 adb 可读取的目录
    -> 拉回电脑，使用独立 PE / CLI / IL 解析器校验
```

构造函数在 SO 加载期间执行，工作线程与注入器恢复目标线程的过程可能交错。项目没有“目标线程已恢复”的显式握手，不能把上图当作自动同步屏障；必须确保注入器及时恢复被暂停的线程，让需要 runtime lock 的调用能正常进行。

auto 只要求从选定模块的 ELF 动态符号表解析以下七个真实导出；不是搜索名称字符串，也不会借用其他 Unity 模块的同名函数：

```text
il2cpp_domain_get
il2cpp_assembly_get_image
il2cpp_image_get_name
il2cpp_thread_current
il2cpp_thread_attach
il2cpp_thread_detach
il2cpp_resolve_icall
```

完成线程附加后，仅调用 `il2cpp_resolve_icall("HybridCLR.RuntimeApi::PreJitClass(System.Type)")` 取得入口地址，**绝不调用 `PreJitClass` 本身**。有界 A64 CFG 解析识别 mask table / token 解码、热更数组访问和 AOT vector walk；读取动态导出的 getter 指令推导 `assembly_image` 和 `image_name` 字段，而不是要求配置这些偏移。

对注册的热更对象 `H`，只检查前 512 bytes 中的指针字段，以 token、owner 和 getter 关系互校出唯一 native image back-pointer。对注册的 HybridCLR image 对象，只检查前 128 bytes 中的唯一 raw object；读取 RawImage vtable 前 16 slots 中的受支持 load prefix，推导 64 位 data、32 位 length、64 位 end。vtable 函数只读不调用。要求 `untag(end)-untag(data)==length`、完整范围可读，以及 DLL 的 `MZ` / `PE` magic 成立；后续还会独立检查保存文件的 PE / CLI / metadata。

`config.max_file_size` **仅限制复制阶段**，不用于筛选 auto raw owner：第二个已识别 raw 即使超过复制上限，也不能排除后制造“唯一候选”。已识别为 raw-like 的对象出现不支持的 load prefix、坏 P/N/E、坏 PE 或未知格式时都 fail closed，不忽略它再挑另一个 raw。唯一但超限的 raw 可以被发现，随后复制阶段仍会明确失败，不发布成功 DLL。

| 有界语义发现项目 | 当前限制 |
| --- | --- |
| Registry CFG 深度 / 函数数 | 3 / 32 |
| 每函数指令数 / 总访问次数 | 128 / 4096 |
| Getter / raw load prefix | 32 条指令，最多 8 个直接 `B` thunk |
| RawImage vtable | 前 16 个 slot 均须可读且指向模块可执行范围；Itanium vptr 位于 `+0` |

未知代码形状、无匹配、歧义或超出边界都 **fail closed**：拒绝对应发现或候选，不继续猜地址、不扩大为全堆扫描，也不静默切换 profile。auto 不调用 `GetUnderlyingInterpreterImage` / `FindImageByAssembly`，不枚举 class / method；旧 profile 的主动私有查询流程见第 6.5 节。

当前实现以**两份注册表的并集**发现对象，不调用 `il2cpp_domain_get_assemblies`。这一点与原恢复方案中讨论的程序集枚举路线不同，应以本项目当前代码为准。

两个发现模式都不会刻意执行 `Execute`、`PreJit`、类构造函数、业务方法或 `LoadCLIHeader` 等初始化解析函数。auto 只读取发现到的解析器 / load prefix 代码，不调用它们。旧 profile 的 class / method 元数据枚举可能触发懒初始化和分配；公开接口、线程 attach 和 icall 解析也不是零副作用保证。

auto 仍限定 metadata-v2 的 mask table / shift 22 token 编码、1024 个热更槽、begin/end/capacity 三指针 AOT vector 和 Itanium vptr-at-0 ABI。PAC、PLT / indirect entry thunk、不同容器和未知代码不支持。它只自动适应**已支持 ABI**内的 RVA 重定位、编译器寄存器分配、GOT / direct 地址生成与字段位置变化，不能宣称任意热更版本通用。本次单一 binary 的实机采集、同样本 IDA / offline semantic 和 synthetic parser / fake-reader 测试均已通过，但不同真实框架版本仍需另行实机验证。

## 3. 环境和文件准备

### 3.1 电脑端

| 工具 | 用途 | 本次验证环境 |
| --- | --- | --- |
| adb | 部署文件、执行设备命令、拉取结果 | 可从当前 PowerShell 调用 |
| Android NDK | 编译 ARM64 SO 和可选测试程序 | `D:/androidSDK/ndk/27.0.12077973` |
| CMake | 生成构建配置 | `D:/androidSDK/cmake/3.22.1/bin/cmake.exe` |
| Ninja | 执行构建 | `D:/androidSDK/cmake/3.22.1/bin/ninja.exe` |
| Python 3 | 独立校验导出文件 | 使用项目内虚拟环境安装依赖 |

只构建 SO 时不需要 Python。Python 以及 `dnfile`、`pefile`、`dncil` 用于导出后的独立检查，不是注入模块的依赖。

### 3.2 设备端

- 目标应用必须是 ARM64 进程，项目不支持直接用于 ARM32 或 x86。
- 设备允许通过 adb 连接，并能以 root 执行注入器和访问应用私有目录。
- 本示例设备的 root 入口是 `/data/local/tmp/kpatch`，使用设备对应的 root key 执行 `su`。
- `/data/local/tmp/AndKittyInjector` 已存在且可执行。
- 目标进程能读取自己的映射，并至少能使用 self `process_vm_readv` 或 `/proc/self/mem` 读取描述符及 raw payload。
- auto 要求目标 `libil2cpp.so` 提供七个真实动态导出，且代码形状、容器和对象关系符合上述受支持 ABI；profile 则要求与配置中的 RVA、代码指纹、对象布局及函数 ABI 匹配。

历史样本设备为 `LVLNINYXKR4L6HAE`，Android API 31，应用版本为 11.0.0、versionCode 1207；以下部署命令仍使用这一环境。示例 SO 使用 Android API 29 构建，不能直接用于系统 API 低于 29 的设备；若调整最低 API，必须重新构建并验证。

### 3.3 需要认识的项目文件

| 文件 | 作用 |
| --- | --- |
| `CMakeLists.txt` | Android ARM64 构建入口 |
| `hybridclr_dump.auto.conf.example` | 推荐的 auto 配置，无目标 RVA / 哈希 / 偏移输入，声明真实 gate |
| `verification/auto-device.conf` | auto 无 gate 实验配置，必须明确授权，不认证完整快照 |
| `hybridclr_dump.conf.example` | 旧完整 profile 的严格 gate 配置，仅作显式备选 |
| `verification/device.conf` | 历史实机使用的完整 profile 无 gate 实验配置 |
| `verification/prepare_device.sh` | 将配置放入当前样本应用的私有目录，设置属主、权限和 SELinux 标签 |
| `verification/export_capture.sh` | 将一次完成的采集复制到 adb 可读取的 staging 目录 |
| `verification/verify_captures.py` | 主机端独立文件校验工具 |
| `verification/requirements.txt` | 主机校验依赖的固定版本 |
| `verification/native_checks.cpp` | 可选原生配置和 PE 校验回归测试 |
| `verification/discovery_checks.cpp` | 可选语义 parser / fake-reader 测试及 offline ELF 校验 |
| `verification/dumper_checks.cpp` / `verification/raw_fixture.cpp` | raw owner / 复制上限 / 公开关联回归；需一起部署测试程序和 fixture SO |
| `include/hybridclr_dumper.h` | 应用主动控制采集时使用的 C API |
| `verification/DEVICE_VALIDATION.md` | 旧 profile 的实机验证记录，不是新 auto / 跨版本证据 |
| `verification/PORTABLE_VALIDATION.md` | 新 auto 单一 binary 实机证据及后续 profile / auto 重复采集记录 |

**两个 shell 辅助脚本当前固定了包名 `com.plantsvszombies3.mengxing`、Android 用户 0 和默认输出目录。只修改下面的 `$package` 变量，不会使这些脚本自动适用于其他应用。** 迁移要求见第 16 节。

## 4. 设置本次操作的变量并检查设备

后续 PowerShell 命令在同一个会话中使用以下变量。全部采用绝对路径，不要求切换电脑端工作目录。

```powershell
$project = "D:/hotupdata_test/HybridCLRRuntimeDumper"
$build = "$project/build/arm64"
$ndk = "D:/androidSDK/ndk/27.0.12077973"
$cmake = "D:/androidSDK/cmake/3.22.1/bin/cmake.exe"
$ninja = "D:/androidSDK/cmake/3.22.1/bin/ninja.exe"

$serial = "LVLNINYXKR4L6HAE"
$package = "com.plantsvszombies3.mengxing"
$activity = "$package/com.unity3d.player.base.StartUpActivity"
$appFiles = "/data/user/0/$package/files"

$rootKey = Read-Host "请输入这台测试设备的 kpatch root key"
$rootPrefix = "/data/local/tmp/kpatch $rootKey su -c"
```

root key 使用该设备已提供的值，不要将真实凭据写入公共配置、脚本或版本库。此示例的 key 不含空格或 shell 特殊字符。

检查工具、设备连接、架构、系统 API、应用安装情况和 root：

```powershell
Get-Command adb, python
Test-Path -LiteralPath $project
Test-Path -LiteralPath "$ndk/build/cmake/android.toolchain.cmake"
Test-Path -LiteralPath $cmake
Test-Path -LiteralPath $ninja

adb devices -l
adb -s $serial get-state
adb -s $serial shell getprop ro.product.cpu.abi
adb -s $serial shell getprop ro.build.version.sdk
adb -s $serial shell cmd package path $package
adb -s $serial shell "$rootPrefix 'id'"
adb -s $serial shell "$rootPrefix 'ls -l /data/local/tmp/kpatch /data/local/tmp/AndKittyInjector'"
adb -s $serial shell "$rootPrefix '/data/local/tmp/AndKittyInjector -h'"
```

关键预期是设备状态为 `device`、架构为 `arm64-v8a`、root 的 `id` 输出包含 `uid=0(root)`。如果 `adb devices` 显示 `unauthorized`，先完成设备上的 USB 调试授权，不要继续注入。

PowerShell 外层使用双引号，设备端传给 `su -c` 的完整命令使用单引号。不要照搬 Bash 的 `&&` 到 PowerShell 5.1。

`build/arm64` 仍可使用。为避免误部署历史产物，新 auto 验证建议在第 5 节前选择独立构建目录，后续 configure、build 和 push 均使用同一个 `$build`：

```powershell
$build = "$project/build/portable-arm64"
```

## 5. 编译注入模块

构造函数 autostart 默认仍为 ON。下面明确开启它，同时编译三种可选原生回归测试程序及 raw fixture SO：

```powershell
if (-not (Test-Path -LiteralPath $project)) {
    throw "项目目录不存在"
}

& $cmake -S $project -B $build -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$ninja" `
    "-DCMAKE_TOOLCHAIN_FILE=$ndk/build/cmake/android.toolchain.cmake" `
    -DANDROID_ABI=arm64-v8a `
    -DANDROID_PLATFORM=android-29 `
    -DANDROID_STL=c++_static `
    -DCMAKE_BUILD_TYPE=Release `
    -DHYBRIDCLR_DUMPER_AUTOSTART=ON `
    -DHYBRIDCLR_DUMPER_BUILD_TESTS=ON

if ($LASTEXITCODE -ne 0) {
    throw "CMake 配置失败"
}

& $cmake --build $build
if ($LASTEXITCODE -ne 0) {
    throw "SO 构建失败"
}

Test-Path -LiteralPath "$build/libhybridclr_dumper.so"
Test-Path -LiteralPath "$build/hybridclr_native_checks"
Test-Path -LiteralPath "$build/hybridclr_discovery_checks"
Test-Path -LiteralPath "$build/hybridclr_dumper_checks"
Test-Path -LiteralPath "$build/libhybridclr_raw_fixture.so"
```

未切换 `$build` 时的产物位置如下；使用独立目录时将 `arm64` 替换为 `portable-arm64`：

```text
D:/hotupdata_test/HybridCLRRuntimeDumper/build/arm64/libhybridclr_dumper.so
D:/hotupdata_test/HybridCLRRuntimeDumper/build/arm64/hybridclr_native_checks
D:/hotupdata_test/HybridCLRRuntimeDumper/build/arm64/hybridclr_discovery_checks
D:/hotupdata_test/HybridCLRRuntimeDumper/build/arm64/hybridclr_dumper_checks
D:/hotupdata_test/HybridCLRRuntimeDumper/build/arm64/libhybridclr_raw_fixture.so
```

`c++_static` 将 C++ 运行库静态链接进模块，不需要额外向应用部署 `libc++_shared.so`。主 SO 使用 `--exclude-libs,ALL` 避免静态 libc++ 符号污染目标应用的符号空间。链接器请求 16 KiB 的 ELF LOAD 对齐，但并不意味着已经在所有 16 KiB 页设备上测试通过。

可选检查 ELF 架构、段对齐和电脑端 SO 哈希：

```powershell
$readelf = "$ndk/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe"
& $readelf --file-header --program-headers "$build/libhybridclr_dumper.so"
& $readelf --dyn-syms "$build/libhybridclr_dumper.so"
Get-FileHash -LiteralPath "$build/libhybridclr_dumper.so" -Algorithm SHA256
```

应看到 `ELF64`、`AArch64`、共享对象类型 `DYN`，LOAD 段的 Align 为 `0x4000`。

当前发布产物为 `build/portable-arm64/libhybridclr_dumper.so`，SHA-256 是 `249e5f09b8b1127c6e320b9352d80fcf76d28076bd703e2724961f7d009cfdec`；重新构建后应记录自己的实际哈希，不把此值当作其他产物的默认身份。该主 SO 实测只有 5 个已定义 C API 导出：`hybridclr_dump_run`、`hybridclr_dump_start`、`hybridclr_dump_state`、`hybridclr_dump_result`、`hybridclr_dump_cancel`，静态 C++ 符号已隐藏。它们不是 auto 所需的七个目标 IL2CPP 导出；raw fixture SO 只用于第 17.3 节测试，不注入目标应用。

## 6. 选择发现模式与 gate 配置

`discovery_mode` 决定如何取得目标位置与字段，gate 开关决定是否具有真实同步保护，两者相互独立。推荐明确填写 `discovery_mode=auto`；省略这个键仍默认 `profile`，用于兼容已经部署的旧完整配置，而不是自动选择或回退。

### 6.1 严格模式：确实有应用侧 gate

严格模式需要应用侧真实的加载/生命周期 gate 在整个发现、查询、复制和最终复核期间阻止相关加载、释放以及 raw 内容修改。

从 `hybridclr_dump.auto.conf.example` 开始，该文件默认声明：

```ini
discovery_mode=auto
stable_window_confirmed=1
allow_ungated_capture=0
dump_pdb=0
```

`allow_ungated_capture` 未配置时默认为 `0`。也可以显式写成 `allow_ungated_capture=0`。

**将配置改成 `stable_window_confirmed=1` 不会自动建立 gate。** 如果你不能控制应用的加载/生命周期，不应使用这个标志冒充有同步保证。外部注入的严格模式同样要求另有实际机制持有 gate；项目不能替你推断或实现它。

有应用集成能力时，第 15 节的同步 API 是更容易明确控制 gate 作用范围的方式。

### 6.2 实验模式：只有外部注入流程，没有 gate

推荐使用 `verification/auto-device.conf` 进行明确授权的 auto 实验，其模式设置是：

```ini
discovery_mode=auto
stable_window_confirmed=0
allow_ungated_capture=1
dump_pdb=0
```

这种模式仍然检查真实导出和语义证据、地址范围、关联对象、raw 描述符、完整覆盖、两遍哈希以及前后注册表。profile 实验仍要求配置的预期代码指纹和精确布局证据。无 gate 开关只放开同步前置条件，不关闭对应发现模式的其他检查。

**所有发现模式**的 raw 复制和第二遍 live hash 已改用 failure-reporting kernel reads：self `process_vm_readv`，必要时回退 `/proc/self/mem`，不再直接对 live payload 执行 `memcpy`。失败或短读会报告失败，不补零。这降低释放 / unmap 导致的 native fault 风险，但不提供 lifetime lock，也不提供 coherent snapshot；运行时函数 ABI 错误或传入对象无效仍可能崩溃。内核读取和指针比较使用去 top-byte tag 地址，manifest 保留原始指针，这不是 PAC 认证。两次相同读数、相同哈希或游戏静止画面都不是生命周期保证。

**实验模式即使所有文件成功，也不会返回 `HYBRIDCLR_DUMP_OK`，不会将 `complete_within_declared_scope` 设置为 `true`。** 后续应分开判断“文件是否完整导出”和“是否有严格同步保护”。

### 6.3 本次示例使用的配置来源

以下主流程选择 auto 无 gate 实验配置，不复用历史 profile 配置：

```powershell
$configSource = "$project/verification/auto-device.conf"
Test-Path -LiteralPath $configSource
```

仅在确实建立应用侧 gate 后，才将来源改为严格 auto 文件：

```powershell
$configSource = "$project/hybridclr_dump.auto.conf.example"
```

这两个 auto 文件都没有函数 RVA / 预期哈希 / registry 地址 / layout 输入，也不要求额外 profile。`profile.name` 可省略，默认 `arm64-semantic-metadata-v2`，只是发现路线标识，不是某个已知二进制的匹配证明。auto 禁止混入 `function.*`、`registry.*`、`evidence.*`、`layout.*` 和 `profile.analysis_sha256`，不能通过添加手工偏移修补一次 auto 失败。未知 / 歧义 fail closed，无静默 profile fallback。

auto 示例默认 `dump_pdb=0`。显式改为 `1` 时可寻找非空 Portable PDB raw 对象，但找不到唯一受支持对象会标记 `NOT_DISCOVERED`，不能据此认证 PDB 不存在，请求的 capture 因而 incomplete。已知 PDB 字段的 profile 才可以在读到 null 时报告 `NOT_PRESENT`。

### 6.4 配置字段说明

| 字段 | 含义和当前示例 |
| --- | --- |
| `discovery_mode` | `auto` 为推荐显式选择；省略时默认 `profile`，两者不会自动回退 |
| `stable_window_confirmed` | 是否声明真实同步窗口，值只能是 `0` 或 `1` |
| `allow_ungated_capture` | 是否显式允许无 gate 实验，默认为 `0` |
| `module_name` | 目标模块 basename，示例为 `libil2cpp.so` |
| `initialization_timeout_seconds` | 等待模块 / domain 及 auto icall 入口的时限，示例 30 秒，不是整个采集或 native 调用超时 |
| `chunk_size` | 单块复制大小，示例 262144 字节，即 256 KiB；非零值必须在 64 KiB 到 1 MiB 之间 |
| `max_file_size` | 复制阶段的单文件上限，示例 536870912 字节，即 512 MiB；最大 `UINT32_MAX`，不用于筛 raw 候选 |
| `dump_pdb` | auto 示例为 `0`；`1` 时请求独立 PDB，auto `NOT_DISCOVERED` 不认证缺失且使 capture incomplete |
| `output_directory` | 可选绝对路径；默认是配置文件所在目录下的 `hybridclr_dll_dump` |
| `profile.name` | auto 可选，默认 `arm64-semantic-metadata-v2`；profile 必填 |
| `profile.analysis_sha256` | 仅 profile 可选的分析样本标识，不是运行时 APK 库哈希；auto 拒绝 |
| `function.*` | 仅 profile：每个目标函数的 RVA、入口校验长度和 SHA-256；auto 拒绝 |
| `evidence.*` | 仅 profile：三处只读代码布局证据的 RVA 和精确字节，不调用这些位置；auto 拒绝 |
| `registry.*` | 仅 profile：热更固定表和 AOT vector 的位置；auto 拒绝 |
| `layout.*` | 仅 profile：原 14 个字段必填，包括零偏移；新增 `layout.assembly_image` 可选默认 `0`；auto 全部拒绝 |

执行用的 chunk、长度限制、初始化等待参数配置为 `0` 时选择程序默认值。等待时限涵盖 module / domain，以及 auto 的 icall 入口就绪，不会中断已进入的 native 调用，也不是整个采集的超时。profile 函数和注册表 RVA 没有内置样本默认值，不能缺失或为零；auto 不输入这些键。

配置解析器只接受严格 ASCII 文本，包括注释。不要在 `.conf` 中加入中文注释或 UTF-8 BOM，不要重复追加同名键。文档中的中文说明不属于配置内容。

### 6.5 旧完整 profile：不支持 auto 时的显式备选

如果 auto 无法识别目标，先保留失败证据、分析真实代码和 ABI。仅在已经完成对应目标的受支持 ABI 分析后，才显式另选 `discovery_mode=profile`；缺省该键的旧配置仍继续走 profile。不能把旧样本数值套给新版本，不能混合两个模式，也不能仅改预期哈希绕过失配。

严格 gate 的 profile 从 `hybridclr_dump.conf.example` 开始；无 gate 的历史样本实验从 `verification/device.conf` 开始。要显式采用这条备选路线时，分别选择：

```powershell
# Only after reviewing a matching legacy profile for the target.
$configSource = "$project/verification/device.conf"
# With a real application gate, use instead:
# $configSource = "$project/hybridclr_dump.conf.example"
```

profile 仍需完整提供 11 个函数各三项配置、3 处代码证据、2 个注册表 RVA 和原 14 个字段偏移，包括 `layout.class_image=0` 也必须显式填写。新增 `layout.assembly_image` 可选，默认 `0`，兼容已经部署的旧 profile 所使用的 assembly `+0` image 指针，不改变原必填要求。样本两个核心私有查询 RVA 是：

```text
GetUnderlyingInterpreterImage: 0x1B77D2C
FindImageByAssembly:           0x1B6DB68
```

函数地址为 `module load bias + RVA`，RVA 不是 ELF 磁盘文件 offset。对象中读出的 heap 指针已经是进程地址，不应再加模块基址。

profile 在 runtime 调用前校验全部 11 个函数和 3 处代码证据；named export 存在时必须与配置地址一致，缺失时才允许经指纹校验的 RVA 路线。auto 则必须有真实动态导出，没有 RVA fallback。手工布局 / 指纹只适用于匹配的构建，不是通用 HybridCLR / Unity ABI。

profile 的热更对象有可用代表方法时，使用真实非数组 class 的 `MethodInfo` 调用 `GetUnderlyingInterpreterImage`；无代表方法时使用已验证的 token / 注册表路线，并记录 `TOKEN_REGISTRY_FALLBACK_NO_METHOD`。AOT 补充对象通过真实 `Il2CppAssembly*` 调用 `FindImageByAssembly`。旧历史样本的四个热更对象均走真实方法查询，未使用回退；这些行为不能写成 auto 的必经流程。profile 使用已知 raw / PDB 字段，但与 auto 一样采用失败可报告的内核读取、独立结构检查和最终审计。

## 7. 将 SO、配置和辅助脚本部署到设备

先确认 staging 父目录存在，然后推送文件：

```powershell
adb -s $serial shell "test -d /data/local/tmp"
if ($LASTEXITCODE -ne 0) {
    throw "设备 staging 目录不可用"
}

adb -s $serial push "$build/libhybridclr_dumper.so" /data/local/tmp/libhybridclr_dumper.so
if ($LASTEXITCODE -ne 0) { throw "SO 推送失败" }

adb -s $serial push $configSource /data/local/tmp/hybridclr_dump.conf
if ($LASTEXITCODE -ne 0) { throw "配置推送失败" }

adb -s $serial push "$project/verification/prepare_device.sh" /data/local/tmp/prepare_hybridclr_dump.sh
if ($LASTEXITCODE -ne 0) { throw "配置安装脚本推送失败" }

adb -s $serial push "$project/verification/export_capture.sh" /data/local/tmp/export_hybridclr_capture.sh
if ($LASTEXITCODE -ne 0) { throw "结果导出脚本推送失败" }
```

`/data/local/tmp/hybridclr_dump.conf` 只是配置的中转文件，构造函数不会自动从这里读取它。必须完成第 9 节，将它安装到应用私有目录。

两个 `.sh` 文件通过 `sh 脚本路径` 运行，不依赖脚本自身的可执行权限。脚本应保持 LF 行尾，避免 Windows CRLF 导致 `set`、路径或条件判断异常。

部署后直到本次结果导出完成，不要覆盖 `/data/local/tmp/libhybridclr_dumper.so`。导出脚本中的 `module.sha256` 计算的是这个磁盘文件在导出时的哈希，不是从活进程重新提取注入模块；中途覆盖会使这份记录与实际注入文件不对应。

## 8. 使用新进程启动目标应用

如果目标进程还加载着旧版 dumper，重复 `dlopen` 同一库可能复用已有模块，构造函数不一定再次执行。更换 SO 后，最可靠的验证方式是重新启动目标应用进程。

确认可以中断当前测试状态后执行：

```powershell
adb -s $serial shell am force-stop $package
adb -s $serial shell am start -W -n $activity
```

这里只停止并重启应用，不执行 `pm clear`，不会主动清空应用数据。但强制停止会中断运行中的业务，应避免丢失尚未保存的测试状态。

如果应用是首次启动，先处理其必要的初始化界面，让应用创建私有目录。确认 `files` 目录存在：

```powershell
adb -s $serial shell "$rootPrefix 'ls -ldZ $appFiles'"
```

取得当前 PID。不要使用 PowerShell 的 `$pid` 作为变量名，它与内置只读 `$PID` 相同。

```powershell
$appPidText = adb -s $serial shell pidof $package
if (-not $appPidText) {
    throw "目标应用尚未运行"
}
$appPid = ($appPidText -join " ").Trim()
if ($appPid -notmatch '^\d+$') {
    throw "未得到唯一 PID，请检查目标进程再继续"
}
$appPid
```

示例 launcher 是 `com.unity3d.player.base.StartUpActivity`，启动后实际 activity 可以转到 `com.game.MainActivity`，这是正常情况。

## 9. 安装应用私有配置并检查权限

以 root 执行已经推送的安装脚本：

```powershell
adb -s $serial shell "$rootPrefix 'sh /data/local/tmp/prepare_hybridclr_dump.sh'"
if ($LASTEXITCODE -ne 0) {
    throw "应用私有配置安装失败"
}
```

脚本按顺序执行以下操作：

1. 检查 `/data/user/0/com.plantsvszombies3.mengxing/files` 和中转配置存在。
2. 如果已有私有配置，以 `hybridclr_dump.conf.backup.<时间戳>` 保存备份。
3. 将完整中转配置复制为应用的 `files/hybridclr_dump.conf`。
4. 从应用 `files` 目录读取 UID/GID，并设置配置文件的属主。
5. 将配置权限设置为 `600`。
6. 执行 `restorecon -F`，恢复应用数据目录匹配的 SELinux 标签。
7. 输出文件权限、属主和标签供检查。

该样本实测文件属主为 `u0_a254`，UID 为 10254。不要把这个 UID 硬编码到其他设备；重新安装或换设备后它可能不同。

构造函数按照进程包名及 Android 用户查找：

```text
/data/user/<user>/<package>/files/hybridclr_dump.conf
/data/data/<package>/files/hybridclr_dump.conf  # 用户 0 的回退位置
```

本样本的实际配置位置是：

```text
/data/user/0/com.plantsvszombies3.mengxing/files/hybridclr_dump.conf
```

**root 注入器不意味着采集线程拥有 root 权限。** SO 在目标应用进程里运行，输出目录必须对应用 UID 可写。默认应用私有输出目录比直接输出到 `/data/local/tmp` 更合适。

自定义 `output_directory` 时，两个现有辅助脚本的默认路径并不会随配置自动变化，特别是 `export_capture.sh` 的源目录必须相应修改。

## 10. 等待 IL2CPP 和相关 DLL 初始化完成

确认模块已加载，可查看目标进程映射：

```powershell
adb -s $serial shell "$rootPrefix 'grep libil2cpp /proc/$appPid/maps'"
adb -s $serial logcat -d "--pid=$appPid" -s Unity:I
```

应进入已经完成相关热更和 AOT 补充数据加载的业务阶段。如果有按场景、按账号或按功能延迟加载的 DLL，要在相应加载完成后采集；尚未加载的文件不会凭空出现在注册表中。

模块出现或 `domain_get()` 返回非空，并不能证明全部热更加载已经结束。项目的 30 秒初始化等待只解决模块 / domain 和 auto icall 入口就绪问题，不是完整加载屏障。

严格模式需要在注入前建立真实应用侧 gate，并持续保持到采集结束。实验模式可以在已完成加载的测试阶段运行，但等待时间和空闲画面仍不能提供同步保证。

不要冻结持有 metadata lock 的线程，再让工作线程主动调用需要同一把锁的查询函数。AndKittyInjector 会短暂停止目标线程用于注入，但随后必须恢复它们，工作线程才能正常调用运行时。

## 11. 注入模块并查看采集日志

执行注入：

```powershell
adb -s $serial shell "$rootPrefix '/data/local/tmp/AndKittyInjector -pkg $package -lib /data/local/tmp/libhybridclr_dumper.so -dl_memfd'"
```

设备端的核心命令是：

```sh
/data/local/tmp/AndKittyInjector -pkg com.plantsvszombies3.mengxing -lib /data/local/tmp/libhybridclr_dumper.so -dl_memfd
```

`-lib` 使用以 `/` 开头的绝对路径。`data/local/tmp/xxx.so` 缺少首个 `/`，不能当作正确的绝对路径使用。

`-dl_memfd` 通过 memfd 方式加载模块，可避免直接从该文件路径加载时的部分限制。它不会提升目标进程权限，也不会解决不支持的语义形状、profile 错误 RVA、函数 ABI 或生命周期问题。

注入器预期输出 `Injection succeeded`。它只表示模块已加载，不代表 DLL 已导出成功。出现 `JNI_OnLoad not found` 是本项目的正常警告，因为项目用 native 构造函数启动，不需要 `JNI_OnLoad`。

随后查看本次进程的 dump 日志：

```powershell
adb -s $serial logcat -d "--pid=$appPid" -s HybridCLRDump:I
```

需要持续观察时，在已经设置上述变量的 PowerShell 会话中运行以下命令，按 `Ctrl+C` 结束观察。若另开终端，必须先重新设置 `$serial` 和本次 `$appPid`，新会话不会自动继承这些变量：

```powershell
adb -s $serial logcat "--pid=$appPid" -s HybridCLRDump:I
```

auto 日志格式示意如下，省略实际地址和会话路径；具体实机证据见第 14.4 节及 portable 验证记录。逐对象日志是否出现取决于执行分支，仍应以 manifest 判读文件状态：

```text
Autostart bootstrap worker active ...
EXPERIMENTAL ungated capture ...
Starting active runtime queries; output: /data/user/0/.../files/hybridclr_dll_dump/<session>
Semantic discovery: hot=..., aot=...; no private queries or configured RVAs
Capture finished: result=1, complete=false, ...
Autostart synchronous dump returned 1
```

其中 `<session>` 的格式是 `<unix-ms>-<pid>-<sequence>`。每次采集创建新的会话目录，不覆盖上次成功结果。应以本次日志中的路径确定 session，不要直接使用历史示例的 session。

**确认看到 `Capture finished` 后，再导出结果。** 没有日志或配置被拒绝时，应先处理问题，不能仅依据注入器成功就进入结果验收。

## 12. 从应用私有目录导出并拉取结果

先查看会话目录，并输入本次日志中的 session 名称：

```powershell
adb -s $serial shell "$rootPrefix 'ls -l $appFiles/hybridclr_dll_dump'"

$session = Read-Host "请输入本次启动日志输出路径末尾的 session 名称"
if ($session -notmatch '^\d+-\d+-\d+$') {
    throw "session 格式不正确"
}
```

普通 adb shell 通常没有权限直接拉取应用私有目录，先由 root 执行 staging 导出：

```powershell
adb -s $serial shell "$rootPrefix 'sh /data/local/tmp/export_hybridclr_capture.sh $session'"
if ($LASTEXITCODE -ne 0) {
    throw "staging 导出失败，请检查源会话和目标目录是否已存在"
}
```

这个脚本会确认源 `manifest.json` 存在，将完整会话复制到以下位置，然后让 adb shell 能读取副本：

```text
/data/local/tmp/hybridclr-verification/<session>/
```

它还记录 `logcat.txt` 和当前中转 SO 的 `module.sha256`。日志快照可能包含其他采集的记录，应结合 PID、时间和 session 判读。

脚本拒绝覆盖已有同名 staging 目录。若此前已经成功导出该 session，且副本未被修改，可以直接拉取已存在的目录，不必再次运行导出脚本，也不要为了绕过检查随意覆盖原始证据。

创建电脑端父目录并拉取完整会话：

```powershell
$captureRoot = "$project/build/captures"
if (-not (Test-Path -LiteralPath "$project/build")) {
    throw "构建目录不存在"
}
New-Item -ItemType Directory -Path $captureRoot -Force | Out-Null

$captureDir = "$captureRoot/$session"
if (Test-Path -LiteralPath $captureDir) {
    throw "本地同名目录已存在，请使用空的目标目录或检查之前的拉取结果"
}

adb -s $serial pull "/data/local/tmp/hybridclr-verification/$session" $captureDir
if ($LASTEXITCODE -ne 0) {
    throw "结果拉取失败"
}
```

保留整个会话目录，而不是只拿 DLL。manifest 中的来源对象、块哈希、覆盖记录、程序集身份、discovery mode、实际语义证据或 profile 匹配记录都是验收的重要证据。

以下是当前样本的目录组织示意；旧 profile 与本次 auto 的程序集名称相同，不代表其他运行也有相同数量 / ID。重新采集仍以自己的 manifest 为准：

```text
<session>/
    manifest.json
    hot_1_Assembly-CSharp.dll
    hot_2_N3xtData.dll
    hot_3_AutomationShared.dll
    hot_4_YetiSimAi.dll
    aot_5_DOTween.dll
    ...
    aot_25_mscorlib.dll
    logcat.txt
    module.sha256
```

`hot_`、`aot_` 和 capture ID 用于保留来源关联，不是程序集真实名称的一部分。不要在校验前改名文件或丢弃 manifest 中记录的重复项。

## 13. 进行独立主机校验

原生模块内的结构检查不是完整的独立验收。主机工具会重新读取拉回的文件，使用与 dumper 不同的 Python PE / CLI / IL 解析器检查它们。新 manifest 为 schema 3，当前主机校验流程同时保留历史 schema 2 支持；应使用与新 SO 配套更新的 `verify_captures.py`，不要用仅支持 schema 2 的旧校验器验收新会话。

创建或复用项目内虚拟环境，并安装固定版本依赖：

```powershell
$verifyEnv = "$project/build/verify-env"
$verifyPython = "$verifyEnv/Scripts/python.exe"

if (-not (Test-Path -LiteralPath $verifyPython)) {
    python -m venv $verifyEnv
    if ($LASTEXITCODE -ne 0) { throw "Python 虚拟环境创建失败" }
}

& $verifyPython -m pip install -r "$project/verification/requirements.txt"
if ($LASTEXITCODE -ne 0) { throw "校验依赖安装失败" }

& $verifyPython -m pip check
if ($LASTEXITCODE -ne 0) { throw "校验依赖有冲突" }
```

依赖版本为 `dnfile==0.18.0`、`pefile==2024.8.26`、`dncil==1.0.2`，不需要执行 DLL 中的托管代码。

执行校验，将机器可读报告写到本次会话目录：

```powershell
$hostReport = "$captureDir/host-verification.json"
& $verifyPython "$project/verification/verify_captures.py" $captureDir --output $hostReport
$verifyExit = $LASTEXITCODE
$verifyExit
```

不要只看 JSON 文件是否生成，应检查退出码及报告的 `status`。

| 主机工具退出码 | 含义 |
| --- | --- |
| `0` | manifest 所列文件和相关记录通过检查，报告为 `PASS` |
| `1` | 文件、覆盖、哈希、结构或 manifest 一致性检查失败 |
| `2` | 输入、依赖或报告输出等运行条件错误 |

独立校验包含：

- 文件实际长度与 `declared_length`、`written_length` 一致。
- 文件实际 SHA-256 同时匹配写出哈希和第二遍 live raw 哈希。
- 所有块无空洞、无重叠地覆盖完整文件，每个块的 SHA-256 正确。
- PE 节、CLI header、metadata stream 和表区间可解析且有界。
- 独立解析的 Assembly name 和 Module MVID 与 manifest 一致。
- schema 3 的 native image name 与保存 DLL 的 metadata Assembly identity 独立对照，不以文件名代替身份验证。
- 有 RVA 的 IL 方法体可解码，分支边界以及 EH 区间可检查。
- 内嵌资源的长度和文件范围合法。
- 已导出的 PDB 通过长度、覆盖和哈希检查，但不独立验证其完整 debug table。
- manifest 声明的计数、关联标志和实验/严格模式结果一致。

这些检查不证明 IL 栈和类型安全、签名语义、业务行为正确或资源内容的语义正确。主机也不会在离线校验时重新调用目标进程，因此关联和语义证据标志是对 manifest 的一致性检查，不是独立重放运行时发现 / 查询，更不是 gate 或跨真实版本兼容性认证。

当配套更新的主机工具 `--help` 已列出 `--compare-with <reference-session-directory>` 时，可用它与保留的 reference session 做**实际文件字节**对比，而不只是比较 manifest 声明的哈希。先确认当前工具包含该选项，再选择参考目录并单独保存报告：

```powershell
& $verifyPython "$project/verification/verify_captures.py" --help
$referenceDir = Read-Host "请输入保留的 reference session 本地目录绝对路径"
if (-not (Test-Path -LiteralPath "$referenceDir/manifest.json")) {
    throw "参考会话缺少 manifest"
}
$comparisonReport = "$captureDir/host-comparison.json"
& $verifyPython "$project/verification/verify_captures.py" $captureDir --compare-with $referenceDir --output $comparisonReport
$LASTEXITCODE
```

对比报告仍需检查退出码和失败原因。本文不预先宣称新 auto 重复采集或本轮旧 profile 回归已逐字节一致；具体 session 和 comparison 结果由 portable 验证记录另行记载。主机 manifest / comparison 回归测试还在扩充，其测试总数不写成固定验收数字。

## 14. 正确判读 manifest 和文件状态

### 14.1 查看本次摘要

在 PowerShell 中查看会话结果和每个对象的状态：

```powershell
$manifest = Get-Content -LiteralPath "$captureDir/manifest.json" -Raw -Encoding UTF8 | ConvertFrom-Json

$manifest.counts | Format-List
$manifest | Select-Object schema_version, discovery_mode, pid, profile, runtime_elf_build_id, `
    supported_registry_abi, payload_copy, semantic_evidence_unchanged, `
    stable_window_confirmed_by_caller, experimental_ungated_capture, `
    registry_snapshots_unchanged, all_registered_inputs_exported, `
    complete_within_declared_scope, result_code, error | Format-List

$manifest.captures | Select-Object capture_id, kind, name, status, `
    association_route, private_query_status, native_name_matches_metadata, `
    @{Name="DllStatus"; Expression={$_.dll.status}}, `
    @{Name="Bytes"; Expression={$_.dll.written_length}}, `
    @{Name="PdbStatus"; Expression={$_.pdb.status}}, `
    @{Name="DllReason"; Expression={$_.dll.reason}} | Format-Table -AutoSize
```

不要把 `associated_native_assemblies` 当作进程全部程序集总数。项目没有枚举没有 retained raw 的普通 AOT 程序集。

如果对象计数为零，即使当前空集合的检查没有报错，也不能就此宣称游戏 DLL 都导出了。应确认采集时点、发现模式 / 证据或 profile，以及实际加载流程。

schema 3 新增 `discovery_mode`、`resolved_registry_rvas`、`resolved_identity_layout`、每候选的 `resolved_owner_layout` 与每 blob 的 `raw_layout`。`payload_copy=FAILURE_REPORTING_KERNEL_READ` 说明当前 raw 读取路线，不代表存在生命周期保护。

auto 的 `semantic_discovery_evidence` 记录实际读取的 semantic code / GOT / vptr / vtable 的地址、长度和 SHA-256；`semantic_evidence_unchanged` 记录最终复核。`function_bindings` 中的 `actual_sha256` 是实测值，auto 没有预期 known hash；这些证据用于追溯和变化检测，不是对任意代码的 ABI 安全证明。

成功的 auto 关联路线为 `association_route=SEMANTIC_REGISTRY_PUBLIC_API`，并保留 `private_query_status=NOT_REQUESTED`，**不是 `MATCH`**。`query_confirmed=true` 只代表所选公开路线确认，不代表执行过私有查询；auto 没有 representative method。旧 profile 私有查询成功才可为 `MATCH`，无方法路线为 `NOT_RUN_NO_METHOD`。`native_name_matches_metadata` 则单独比较 native image name 与保存 DLL 的 metadata Assembly name，不由其中一个生成另一个。

历史 schema 2 没有这些新字段；查看旧 session 时不能给它补写 auto 证据或改模式。

### 14.2 文件和状态的含义

| 文件或状态 | 含义 |
| --- | --- |
| `.dll`，blob 状态为 `COMPLETE` | 全长度导出、copy/live 哈希匹配，并通过支持范围内的原生结构检查 |
| `.pdb`，状态为 `COMPLETE` | 独立 PDB 对象导出成功，不应与 DLL 合并 |
| `.partial` 或 blob 状态为 `PARTIAL` | 复制、取消、描述符、哈希或 I/O 等未通过，不能视为完整 DLL |
| `.dll.invalid.bin` / `.pdb.invalid.bin` | 全字节导出完成但后续结构检查拒绝；auto 的未知 raw 格式 / 坏 PE magic 会先拒绝 owner，不保证生成此文件 |
| `HOT_UPDATE_COMPLETE` | 热更对象对应的 DLL 完成 |
| `AOT_SUPPLEMENT_COMPLETE` | AOT 补充对象对应的 DLL 完成 |
| `PENDING_INITIALIZATION` | 对象身份、所选关联路线或 retained raw 尚未验证，可能是未初始化、placeholder 或不受支持，不应输出伪 DLL |
| `NOT_PRESENT` | 仅已知 PDB 字段的 profile 读到 null 时认证不存在，不等于 DLL 失败 |
| `NOT_DISCOVERED` | auto 请求 PDB 但未正向发现唯一受支持对象；不认证不存在，capture incomplete |
| `DISABLED` | 配置关闭了 PDB 采集 |

`PENDING_INITIALIZATION` 也可能由语义发现不支持、歧义、错误布局或失配产生，不应仅凭名称断定稍后一定能恢复。应结合 `reason`、发现证据 / profile 和采集时点分析。即使 DLL blob 为 `COMPLETE`，native name / metadata 身份失配也会使候选关联失败，不能只验 blob 而忽略候选状态。

不要将 `.invalid.bin` 直接重命名成 `.dll`，或修改 manifest 状态来制造通过。先用独立解析器判断是否是校验器兼容性问题或真实格式异常，再修复代码、重新构建并重新采集。

### 14.3 原生结果码与主机退出码是两回事

| 原生 `result_code` | 含义 |
| --- | --- |
| `0` | 已声明真实 gate，声明范围内所有对象完成；实际 gate 仍是调用方前置条件 |
| `1` | 有未完成对象/文件，或者本次是显式无 gate 实验 |
| `-1` | 传入选项或配置无效，可能在创建 manifest 前就拒绝 |
| `-2` | 已有采集运行中，新的采集未被接受 |
| `-3` | 不支持 / 歧义的发现、profile、运行时、设置或 I/O 等错误 |
| `-4` | 协作式取消 |

对没有 gate 的一次逐文件成功采集，正确组合可以是：

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

同时主机工具可以退出 `0` 并报告 `PASS`。这表示所有列出的文件通过验收，但不能认证一个受同步保护的完整运行时快照。

严格模式要求 gate 真实存在、会话审计及请求的 DLL/PDB 均完成，才可以得到 `result_code=0` 和 `complete_within_declared_scope=true`。auto 还需实际语义证据复核未变；若请求 PDB 得到 `NOT_DISCOVERED`，即使 DLL 均成功也不满足完成条件。仅手工把确认字段改为 `1` 不会满足实际生命周期要求。

### 14.4 新 auto 单一 binary 实机结果

新 auto 已实际注入成功，session `1791196054447-17919-0`，使用 `verification/auto-device.conf`，未输入任何手工函数 RVA、字段偏移、registry 地址或预期哈希：

| 项目 | 本次观测 |
| --- | --- |
| 目标 GNU build ID | `b1ab380823c8af07794776c401e3a6ca57de9441` |
| PID / 存活 | `17919`，采集及独立 host 校验后进程仍存活 |
| DLL | 25/25：4 个热更 + 21 个 AOT 补充，合计 26,188,800 bytes |
| 独立 host | `PASS`；116 chunks、165,802 IL 方法体、6,026 EH 子句检查通过 |
| 绑定 / 关联路线 | 7 个真实动态导出；25 个候选均为 `SEMANTIC_REGISTRY_PUBLIC_API`，私有查询 `NOT_REQUESTED` |
| 关联 / 身份 | 全部 `association_verified`、`query_confirmed`、`native_name_matches_metadata` 为 `true` |
| 最终复核 | `semantic_evidence_unchanged=true`、`registry_snapshots_unchanged=true`、`all_registered_inputs_exported=true` |
| 无 gate 结果 | `result_code=1`，`complete_within_declared_scope=false`，不认证 coherent snapshot |
| PDB | 全部 `DISABLED`，不是 `NOT_PRESENT`；未验证 PDB absence 或实际 PDB 导出 |

旧 profile 回归 session `1791203411317-27900-0` 和第二次 auto session `1791203675884-28745-0` 也已实测通过。三次新采集各导出 25 个 DLL，实际长度、SHA-256 和 Assembly/MVID 多重集比对均一致，并与历史 schema 2 基准相符；不是仅比较 manifest 中写下的哈希。最终应用配置已恢复为 auto 实验配置。

会话文件分别位于 `build/captures/<session>/`，包含各自的 `host-verification.json`。详细设备证据、208 项检查结果和复验命令见 [PORTABLE_VALIDATION.md](verification/PORTABLE_VALIDATION.md)。这里只确认当前同一个目标 binary 在不同 ASLR 基址下的真实设备结果，不能据此声称跨真实 framework 版本已验证，也不能把 kernel-read 或不变的证据当作 lifetime gate。

### 14.5 旧 profile 历史结果，不是新 auto 证据

2026-10-05 旧完整 profile 修复后采集的 session 为 `1791179923565-12005-0`，使用 `verification/device.conf` 及历史 schema 2：

| 项目 | 结果 |
| --- | --- |
| 热更 DLL | 4/4：Assembly-CSharp、N3xtData、AutomationShared、YetiSimAi |
| AOT 补充 DLL | 21/21 |
| DLL 总字节数 | 26,188,800 |
| copy/live/主机文件 SHA-256 | 全部一致 |
| 完整覆盖块 | 116 个，全部通过 |
| 独立检查 IL 方法体 | 165,802 个，全部通过 |
| EH 子句边界检查 | 6,026 个，全部通过 |
| PDB | 25 个对象均为 `NOT_PRESENT`，未测试实际 PDB 导出 |
| 与首次冷启动采集对比 | 25 个文件逐字节一致 |
| 无 gate 的会话结果 | `result_code=1`，不认证严格完整快照 |

历史成功目录和报告保存在项目的 `build/captures`、`build/final-capture-verification.json` 和 `build/cross-run-verification.json`。其中 25 个 `NOT_PRESENT` 来自 profile 已知 PDB 字段，不能转述为 auto 认证了 PDB absence。新 auto 实机结果已单独列在第 14.4 节；重新采集时选择新 session 并重新校验，不复用这份旧证据宣称新实现或跨真实框架版本验证完成。

## 15. 可选：由应用主动控制严格采集

如果能修改自己的测试应用，或者有已经合法集成到应用中的 native 控制组件，可以使用导出的 C API，而不是仅依赖构造函数自动启动。

重新构建时将 `HYBRIDCLR_DUMPER_AUTOSTART` 设为 `OFF`，避免库加载时自动启动一次不可控采集：

```powershell
& $cmake -S $project -B $build -DHYBRIDCLR_DUMPER_AUTOSTART=OFF
if ($LASTEXITCODE -ne 0) { throw "CMake 配置失败" }
& $cmake --build $build
if ($LASTEXITCODE -ne 0) { throw "构建失败" }
```

这是另一种集成方式。关闭 autostart 后，仅执行前面的 AndKittyInjector 命令不会自动 dump，必须由应用组件实际调用 API。

应用在相关加载完成后获取自己实现的高层生命周期 gate，配置文件声明严格模式，随后调用：

```cpp
#include "hybridclr_dumper.h"

// 应用侧真正的加载/生命周期 gate 已持有，且覆盖后续全部采集。
HybridClrDumpOptions options{};
options.struct_size = sizeof(options);
options.abi_version = HYBRIDCLR_DUMPER_ABI_VERSION;
options.config_path = "/data/user/0/com.plantsvszombies3.mengxing/files/hybridclr_dump.conf";
options.stable_window_confirmed = 1;

int result = hybridclr_dump_run(&options);
// 同步采集返回后，应用才可以释放高层 gate。
```

这段代码是集成时的调用片段，不是独立可执行程序。gate 需要应用按自己的加载和 raw 所有权协议实现，不能用一个无人配合的局部互斥锁替代。

不要持有 HybridCLR 自己的 metadata lock 跨越调用，查询函数可能会再次获取它。线程附加由项目正常处理，只 detach 本组件自行 attach 的线程。

异步 API `hybridclr_dump_start()` 返回 `0` 只表示接受请求，不代表完成。保持 gate，等待 `hybridclr_dump_state()` 为 `HYBRIDCLR_DUMP_FINISHED`，再读取 `hybridclr_dump_result()`。`FINISHED` 不是线程 join 或 SO 卸载屏障，不要据此立即 `dlclose`。

`hybridclr_dump_cancel()` 是协作式取消，在等待、发现边界和复制块处生效，不能强行中断一个已经进入的 native 查询。

## 16. 重复采集、更新模块和迁移到其他应用

### 16.1 重复采集

修改配置文件不会自动启动下一次采集。已经被接受的采集使用加载时复制的配置，也不会实时读取你的后续修改。

纯外部注入流程重复采集时，按以下顺序操作：

1. 确认当前采集完成，将整个 session 导出并拉回电脑。
2. 保留本次实际注入的 SO、配置、manifest、日志和主机报告。
3. 若需要更新 SO，重新构建并部署，不要假设旧进程会重新运行构造函数。
4. 停止并重新启动目标应用，不清空应用数据。
5. 安装本次完整配置，等待所需加载阶段。
6. 在符合严格 gate 或明确授权实验条件的情况下重新注入。
7. 选择新的 session，重新导出并验证。

应用集成方式可以在上一轮结束后通过 API 发起另一轮采集；同一时刻只允许一轮采集。

### 16.2 更换应用或 libil2cpp 构建

包名相同也不能保证库版本相同。更新 APK、HybridCLR、Unity 或厂商保护逻辑后，要重新确认当前 runtime。优先在有授权的测试环境使用不带目标位置 / 布局输入的 auto，检查本次 schema 3 证据与独立文件校验；失败时停止猜测，分析后再决定是否显式采用匹配的完整 profile。

| 需要检查或调整的内容 | 原因 |
| --- | --- |
| `$serial`、`$package`、启动 activity、Android 用户目录 | 设备、进程和 app data 路径不同 |
| 两个 shell 脚本中的固定路径 | 当前脚本专用于样本包名、用户 0 和默认输出目录 |
| auto 的七个真实动态导出、CFG / getter / raw prefix 证据及唯一关联 | 支持范围内可适应 RVA / 寄存器 / GOT-direct / 字段位置变化；未知或歧义拒绝，不混入手工键 |
| 仅 profile：全部函数 RVA、入口指纹和原型 | 错误函数地址或 ABI 可能直接崩溃 |
| 仅 profile：3 处布局代码证据 | 字段布局依据可能变化 |
| 仅 profile：2 个注册表 RVA、原 14 个必填偏移和可选 `layout.assembly_image` | 这些不是跨版本稳定 ABI；后者省略时默认 `0` |
| 两种模式的 metadata-v2 mask / shift 22、1024 hot、三指针 vector 和函数 ABI；auto 的 Itanium vptr `+0` | 当前只支持有限 ABI；PAC、PLT / indirect thunk、不同容器或未知代码不能靠 auto 或改哈希解决 |
| 可选回归测试的 DOTween fixture 和 tables header file offset | 样本专用，不能用于任意 DLL |

可以使用 IDA MCP 对当前库进行有界分析，核对 icall 入口的 token / 注册表 / vector 语义、getter、raw 前缀和关联字段；选择 profile 时还要核对两个核心私有查询。对于入口被 instrumentation 改写的情况，应先查明真实代码和调用入口，不能只将 profile 期望哈希改成当前读数就盲目调用，也不能把 auto 的实测哈希当作已知可信版本认证。

profile 的分析样本 SHA-256 不等于 APK 原始 SO 哈希；运行时 GNU build ID、profile 预期 / 实际入口指纹及 auto 实际语义证据各有含义。注入 dumper 的 SO 哈希又是另一项身份信息，不要混为同一个库的指纹。同样本的 IDA / offline 和 synthetic 测试不替代不同真实 HybridCLR 版本的设备验证。

## 17. 可选：运行原生回归测试

第 5 节开启 `HYBRIDCLR_DUMPER_BUILD_TESTS=ON` 后，会生成 `hybridclr_discovery_checks`、`hybridclr_native_checks`、`hybridclr_dumper_checks` 及后者依赖的 `libhybridclr_raw_fixture.so`。这些测试不调用目标 IL2CPP / HybridCLR runtime API，也不执行发现到的目标代码或 DLL 方法。以下计数是本次构建已通过的摘要，后续新增测试以实际输出和验证记录为准。

### 17.1 语义 parser / fake-reader 与 offline 测试

无参数运行 discovery checks，检查有界 CFG、寄存器和字段变化、GOT / direct 地址、getter / raw prefix、失败读取、未知形状、歧义与预算拒绝等 synthetic 情形：

```powershell
adb -s $serial push "$build/hybridclr_discovery_checks" /data/local/tmp/hybridclr_discovery_checks
if ($LASTEXITCODE -ne 0) { throw "语义测试程序推送失败" }
adb -s $serial shell "$rootPrefix 'chmod 755 /data/local/tmp/hybridclr_discovery_checks'"
adb -s $serial shell "$rootPrefix '/data/local/tmp/hybridclr_discovery_checks'"
```

本次 98 个 synthetic 测试已通过，摘要为：

```text
PASS 98 FAIL 0
```

程序还提供 `--elf file pre_jit_class getter1 getter2 raw_vtable` 的可选离线模式，对重建的 base-zero ELF 只读校验；四个位置由测试命令明确提供，不是 auto 采集配置输入，也不会执行目标函数。getter1 / getter2 分别使用 assembly-image 和 image-name 入口。ARM64 测试程序需在相应设备运行，不能直接在 Windows 执行。同样本 IDA / offline 和 synthetic 测试不能算作跨真实框架版本验证。

### 17.2 旧 profile 配置和 PE fixture 回归

`hybridclr_native_checks` 检查配置解析和 PE 校验，以下保留旧 profile 的样本 fixture 步骤。

此程序的配置 fixture 要求 `stable_window_confirmed=0`、`allow_ungated_capture=1`，因此单独部署测试配置，不覆盖实际采集配置：

```powershell
adb -s $serial push "$build/hybridclr_native_checks" /data/local/tmp/hybridclr_native_checks
adb -s $serial push "$project/verification/device.conf" /data/local/tmp/hybridclr_test.conf
adb -s $serial shell "$rootPrefix 'chmod 755 /data/local/tmp/hybridclr_native_checks'"
```

对本文同一构建的 DOTween 文件，已确认 metadata tables header 的**文件 offset**为 `0x12000`。它不是内存地址，也不是 RVA。

在第 12 节 staging 目录含有该文件的前提下运行：

```powershell
adb -s $serial shell "$rootPrefix '/data/local/tmp/hybridclr_native_checks /data/local/tmp/hybridclr_test.conf /data/local/tmp/hybridclr-verification/$session/aot_5_DOTween.dll 0x12000'"
```

旧验证记录中的 15 项属于旧测试程序；当前构建用同一 fixture 已通过 31 项检查，摘要如下：

```text
PASS 31 FAIL 0
```

测试包含接受 Cecil 的 `Reserved2=0x0a`、标准 `Reserved2=1` 和未生效 Sorted 位，拒绝实际 Valid 表 45、损坏 header、截断文件，以及模式相关配置、auto / 手工混用拒绝、profile 可选 assembly 字段和 live / tagged / stale-VMA kernel-read 回归。

若 DLL 不叫 `aot_5_DOTween.dll`、来自不同构建，或者没有 DOTween，不能照抄这个命令。应选择正确 fixture，并先独立确认 tables header file offset。历史首次采集中的同内容 `.dll.invalid.bin` 也可作为该样本的回归 fixture。

### 17.3 Raw owner / copy limit / 公开关联回归

`hybridclr_dumper_checks` 依赖真实映射的测试库 `libhybridclr_raw_fixture.so`。两者必须一起部署；只推送可执行文件会缺少共享库。测试在独立测试进程运行，不向应用注入 fixture：

```powershell
adb -s $serial push "$build/hybridclr_dumper_checks" /data/local/tmp/hybridclr_dumper_checks
if ($LASTEXITCODE -ne 0) { throw "dumper 测试程序推送失败" }
adb -s $serial push "$build/libhybridclr_raw_fixture.so" /data/local/tmp/libhybridclr_raw_fixture.so
if ($LASTEXITCODE -ne 0) { throw "raw fixture SO 推送失败" }
adb -s $serial shell "$rootPrefix 'chmod 755 /data/local/tmp/hybridclr_dumper_checks'"
adb -s $serial shell "$rootPrefix 'LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/hybridclr_dumper_checks /data/local/tmp'"
```

本次摘要为 `PASS 36 FAIL 0`。测试覆盖双 raw（含超限对象）仍歧义、唯一超限 raw 的复制失败、坏 P/N/E / PE / 未知格式不制造假唯一，以及公开关联字段变化等。最后一个 `/data/local/tmp` 是可写临时父目录；它不是目标应用配置目录。safe kernel-read 回归也不认证实际应用存在 gate。

## 18. 常见问题排查

| 现象 | 重点检查 |
| --- | --- |
| `unauthorized` / `offline` / 多设备误选 | USB 调试授权和 `$serial`；所有操作都明确使用 `-s` |
| root `id` 没有 `uid=0` | kpatch 路径、设备 root key、`su -c` 的引号 |
| 注入器文件不存在或不可执行 | `/data/local/tmp/AndKittyInjector` 的位置、ARM64 架构和执行权限 |
| `Injection succeeded` 但没有采集日志 | autostart 是否为 ON、是否复用了旧模块、是否进入了正确 PID、配置是否存在 |
| `No app-private hybridclr_dump.conf found` | 配置是否只留在 tmp；是否完成安装脚本；实际进程名/用户是否符合路径推断 |
| `Cannot stat/open configuration` | 文件属主、`600` 权限、目录访问权限和 SELinux 标签；不要只用 root 验证能否读取 |
| 配置提示 unknown / duplicate / not strict ASCII | 是否加了中文注释、BOM、重复键或拼错键名；检查对应模式要求，不必给 auto 添加旧 profile |
| Auto 配置拒绝手工 evidence / offsets | 删除误混入的 `function.*` / `registry.*` / `evidence.*` / `layout.*` / `profile.analysis_sha256`；不要只改模式名套用完整旧配置 |
| 无 gate 配置被拒绝 | 必须同时为 `stable_window_confirmed=0`、`allow_ungated_capture=1`，且仅用于明确授权实验 |
| `Module not found` 或 domain readiness timeout | 应用是否加载 IL2CPP、模块名是否正确、是否选错进程、是否提前注入 |
| Auto requires a real module export | 七个真实动态导出是否都存在于选定 ELF；auto 没有配置 RVA fallback |
| Unsupported / ambiguous auto discovery | CFG / getter / raw prefix 是否属于支持范围，预算、PAC / PLT / indirect thunk 或容器是否失配；保留证据，不扩大扫描或静默回退 |
| `Function address/config mismatch` | 仅 profile：动态符号地址与配置是否来自同一构建，RVA 是否误用了文件 offset |
| `Code fingerprint mismatch` / 布局证据失配 | 仅 profile：库版本变化、入口被 Hook、错误 profile；不要关闭检查或随便替换哈希 |
| AOT vector 无法读取或边界异常 | auto 语义证据或 profile registry RVA、三指针布局、初始化和并发扩容；不要扩大扫描范围盲找对象 |
| `PENDING_INITIALIZATION` | 读取 reason，检查语义支持 / 唯一性、关联字段、placeholder、加载时点或 profile |
| 请求 PDB 得到 `NOT_DISCOVERED` | auto 未正向识别唯一非空 Portable PDB，不能改为 `NOT_PRESENT`；不需要 PDB 时在下一轮明确设 `dump_pdb=0` |
| `private_query_status=NOT_REQUESTED` | auto 的正常公开路线，不是私有查询失败，也不能改为 `MATCH` |
| native name 与 metadata 失配 | 检查候选身份、raw 所有权及独立 Assembly name；DLL blob 完整不等于关联成功 |
| raw 的 P/N/E 不一致或范围不可读 | raw 字段布局、32 位长度读取、指针标签、对象生命周期、大小上限 |
| Raw owner 歧义或超限 | `max_file_size` 只限制复制，不可筛掉另一 owner；坏 raw-like 不被忽略，不挑另一对象冒充唯一 |
| 输出目录 Permission denied | 输出目录是否对应用 UID 可写；root 注入器不会将应用工作线程变成 root |
| `.partial` 或 live/output 哈希不同 | 复制失败、文件 I/O、描述符变化或 raw 并发修改；不要补零或伪造覆盖 |
| `.invalid.bin` | 独立检查实际格式与校验器支持范围；当前代码已修复样本的 Cecil header 和 Sorted 位误拒绝 |
| export 脚本返回失败 | manifest 是否已经发布；session 是否正确；staging 目标是否已经存在 |
| `adb pull` 无法读取私有目录 | 先通过 root 导出到 staging，不要给整个应用数据目录开放权限 |
| 主机工具缺 dnfile / dncil / pefile | 使用 `$verifyPython` 对应的虚拟环境安装 requirements，不要混用其他 Python |
| 原生 `result=1`，但 DLL 均成功 | 检查无 gate、请求 PDB 的 `NOT_DISCOVERED` 或关联 / 证据审计失败；依据完整 manifest 和主机报告判断 |
| 主机工具只接受 schema 2 | 使用与当前 SO 配套更新的校验器；历史 schema 2 支持不意味着旧工具自动认识 schema 3 |
| dumper checks 缺 `libhybridclr_raw_fixture.so` | 同时部署 fixture，设置 `LD_LIBRARY_PATH=/data/local/tmp`；不需要向目标应用注入测试库 |
| 目标进程崩溃或查询长时间不返回 | 错误 ABI、生命周期竞争、错误标签、锁持有者被冻结；停止当前尝试并先分析原因 |

检查目标进程是否仍在，以及查看 crash buffer：

```powershell
adb -s $serial shell pidof $package
adb -s $serial logcat -d -b crash
```

native crash 的 tombstone 日志可能由另一个进程输出，不能只依赖 `--pid=$appPid` 的普通日志过滤。另一方面，设备的 crash buffer 也可能包含其他应用或历史错误，要结合时间、PID、库名和调用栈判断。

不要把应用在注入前已存在的托管错误自动归因于 dump。本样本在最终注入前就出现过缺失脚本、资源和 TMPro 错误，实机验证记录已注明；它们不属于本项目完成的修复范围。

## 19. 完成一次采集的检查清单

1. 已确认授权、设备、root、目标包名、ARM64 进程和受支持的 runtime ABI；auto 不代表任意版本通用。
2. 已构建最新 SO，纯注入流程的 autostart 为 ON。
3. 已选择真实严格 gate 或明确的无 gate 实验模式，没有把等待或空闲画面当作同步保证。
4. 对应模式的 ASCII 配置已安装到应用私有目录，属主、权限和 SELinux 标签正确；auto 未混入手工 profile，PDB 请求范围明确。
5. 应用已完成本次要覆盖的加载阶段，注入后目标线程已恢复。
6. 注入器成功后，确实观察到 dump 启动和完成日志。
7. 本次 session 的所有候选都有明确状态，计数和采集范围符合实际加载情况；auto 公开路线 / `NOT_REQUESTED`、实际证据和 native / metadata 身份已检查。
8. 完整 session 已导出并拉回，保留 DLL/PDB、manifest、日志和实际模块身份记录。
9. 独立工具校验完成，已检查退出码、JSON status 和失败原因。
10. 分开记录逐文件完整性、同步保证和跨版本验证范围；实验模式不声称严格快照，旧 profile 历史结果不充当新 auto 证据。
11. 原始结果和失败证据没有被改名、补零、覆盖或篡改状态。
12. 没有在工作线程或 API 仍活跃时卸载 SO；后续采集使用新 session。

## 20. 相关文档和代码

- [项目 README](README.md)：配置 schema、导出 API 和实现范围。
- [实机验证记录](verification/DEVICE_VALIDATION.md)：旧 profile 的编译、注入、修复和验收证据，不是新 auto 记录。
- [Portable 验证记录](verification/PORTABLE_VALIDATION.md)：新 auto 单一目标 binary 的实机证据，以及后续 profile 回归 / 重复采集与字节对比记录。
- [运行时恢复方案](../HybridCLR_Runtime_DLL_Recovery_Plan.md)：旧主动查询路线和 raw 文件恢复的分析依据；当前模式以项目实现为准。
- [SO 分析指南](../HybridCLR_SO_Analysis_Guide.md)：样本分析背景。
- `src/entry.cpp`：构造函数启动、选项检查和 C API。
- `src/config.cpp`：模式相关配置、ASCII、混用拒绝和实验 opt-in 校验。
- `src/discovery.cpp` / `src/discovery.h`：有界 A64 CFG / getter / raw prefix 语义发现，不执行发现代码。
- `src/platform.cpp`：模块定位、真实动态符号解析、映射检查和失败可报告的内核读取。
- `src/dumper.cpp`：auto 公开 / profile 私有路线、注册表与证据审计、完整复制和 schema 3 manifest。
- `src/pe.cpp`：原生 PE / CLI / metadata 结构检查。
- `verification/verify_captures.py`：离线完整性和独立结构校验。
- `verification/discovery_checks.cpp`：synthetic parser / fake-reader 测试及可选 offline ELF 检查。
- `verification/dumper_checks.cpp` / `verification/raw_fixture.cpp`：测试专用 raw 所有权 / 复制上限和公开关联回归。
