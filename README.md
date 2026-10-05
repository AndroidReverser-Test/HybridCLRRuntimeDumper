# HybridCLRRuntimeDumper

**中文** | [English](README_EN.md)

在 Android ARM64 进程内，通过主动调用 IL2CPP/HybridCLR 接口并读取运行时保留的 raw 数据，导出原文件布局的 .NET DLL 和可选 Portable PDB。

项目产物是 `libhybridclr_dumper.so`，支持应用主动调用和外部注入后自动启动。不包含注入器，不依赖加载 Hook，不扫描整个堆，也不从 native 代码或解释器 IR 重建 DLL。仅用于自己拥有或已获授权分析的应用。

## 导出范围

- 当前已注册、仍保留完整 raw 副本的热更新 DLL。
- 当前已注册的 AOT 补充 DLL，包括 SUPERSET 输入。
- 可识别且仍保留 raw 副本的 Portable PDB，单独保存。

这里的“全部”仅指上述已保留输入的并集，**不是进程内所有程序集**。没有补充 raw 数据的普通 AOT 原始 DLL、尚未加载或已卸载的文件、已经释放的输入，以及只存在于 IR 中的修改均不在恢复范围内。

## 实现流程

1. 读取配置，等待目标模块和 IL2CPP domain 就绪，必要时附加当前线程到 IL2CPP。
2. 定位热更新注册表和 AOT 补充注册表，建立候选集并通过运行时接口确认对象身份。
3. 定位 retained raw 对象，按其完整文件长度分块读取，检查两遍 SHA-256、描述符和保存文件的 PE/CLI 元数据。
4. 复核注册表、对象关联及发现证据，输出文件和 `manifest.json`。

推荐显式设置 `discovery_mode=auto`：通过有界 A64 语义分析定位注册表及字段，无需配置 RVA、预期代码哈希或对象偏移。它只解析 `HybridCLR.RuntimeApi::PreJitClass(System.Type)` 的入口地址并读取代码，**不执行 PreJitClass、发现到的解析器或业务方法**。

Auto 要求选定模块提供以下七个真实动态导出：

```text
il2cpp_domain_get
il2cpp_assembly_get_image
il2cpp_image_get_name
il2cpp_thread_current
il2cpp_thread_attach
il2cpp_thread_detach
il2cpp_resolve_icall
```

Auto 仅支持当前实现识别的 metadata-v2 ABI，包括 shift 22 token 编码、1024 个热更槽、三指针 AOT vector 和 Itanium vptr-at-zero 布局。未知代码、歧义、PAC 或不支持的容器会被拒绝，不会自动回退到 profile，**不能视为任意 HybridCLR 版本通用**。

`discovery_mode=profile` 是手工备选：需针对目标构建分析完整的函数 RVA、代码指纹、注册表和布局，随后主动调用已校验的 HybridCLR 私有查询。参见 [profile 配置示例](hybridclr_dump.conf.example)，其中的样本值不可直接用于其他构建。省略 `discovery_mode` 时默认选择 `profile`，而非 auto；auto 禁止混入 `function.*`、`registry.*`、`layout.*`、`evidence.*` 和 `profile.analysis_sha256`。

## 构建

需要 Android NDK、CMake 3.22+ 和 Ninja。仅支持 Android `arm64-v8a`，不需要 APK、Gradle、Java 或 HybridCLR 源码。

在项目根目录执行以下 PowerShell 命令，先设置 `ANDROID_NDK_HOME`，并确保 `cmake`、`ninja` 在 `PATH` 中：

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

产物：`build/arm64/libhybridclr_dumper.so`。示例选择 API 主动调用模式；若需要注入后自动采集，将 `HYBRIDCLR_DUMPER_AUTOSTART` 改为 `ON` 后重新配置并构建。该选项的项目默认值为 `ON`，不要将上述 `OFF` 构建用于期待自动采集的注入流程。

## 配置与同步

配置必须由目标应用 UID 可读，输出目录必须由该 UID 可写。严格 auto 配置可从 [hybridclr_dump.auto.conf.example](hybridclr_dump.auto.conf.example) 开始：

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

**仅在真实的应用侧加载/生命周期 gate 已持有时使用此配置。** Gate 必须在整个发现、复制和复核期间阻止相关加载、raw 释放及修改；确认标志不实现任何同步。不要持有 HybridCLR 自己的 metadata lock 跨越采集调用，运行时接口可能再次获取它。

没有 gate 的授权实验应使用 [verification/auto-device.conf](verification/auto-device.conf)，即将上述两个同步设置改为：

```ini
stable_window_confirmed=0
allow_ungated_capture=1
```

无 gate 采集即使所有文件通过检查，也不会返回完整成功。两遍哈希、相同注册表快照或空闲画面不能代替生命周期保护。Raw 读取使用 self `process_vm_readv`，失败时尝试 `/proc/self/mem`；失败或短读不补零，但这些检查不能保证原子快照，也不能消除无效运行时调用导致崩溃的风险。

| 设置 | 含义 |
| --- | --- |
| `module_name` | 目标模块 basename，默认 `libil2cpp.so` |
| `initialization_timeout_seconds` | 默认 30 秒，仅限制模块、domain 和 auto icall 就绪等待，不是全程或 native 调用超时 |
| `chunk_size` | 默认 256 KiB，非零值须为 64 KiB 至 1 MiB |
| `max_file_size` | 默认 512 MiB，最大 `UINT32_MAX`；仅限制复制，不用于筛选 auto raw owner |
| `dump_pdb` | 上述示例显式关闭；省略时程序默认开启。Auto 未发现唯一 PDB 会报告 `NOT_DISCOVERED` 并使请求不完整，不能据此认证 PDB 不存在 |
| `output_directory` | 可选绝对路径，默认 `<配置文件所在目录>/hybridclr_dll_dump` |

配置使用 ASCII `key=value` 文本，支持 `#` 注释；不要加入中文注释或 BOM。未知键、重复键、无效值及模式混用均会被拒绝。每次调用加载一次配置；修改文件不会影响已接受的采集，也不会自动触发下一次采集。

## 使用方式

### 应用主动调用

关闭 autostart 后，由应用的 native 组件链接该库或加载并解析其导出，使用 [include/hybridclr_dumper.h](include/hybridclr_dumper.h) 中的 C ABI v2。相关 DLL 加载完成、真实 gate 已持有且配置声明 `stable_window_confirmed=1` 后，同步调用：

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

`config_path` 必须是绝对路径。选项只指定配置路径并额外确认稳定窗口，不覆盖文件中的输出目录、发现模式或同步声明。无 gate 实验使用对应实验配置，并将 options 中的确认值设为 `0`。

| API | 用途 |
| --- | --- |
| `hybridclr_dump_run(options)` | 当前线程同步采集，返回最终结果 |
| `hybridclr_dump_start(options)` | 读取并复制配置后启动 native worker；返回 `0` 仅表示接受请求 |
| `hybridclr_dump_state()` | 查询 `IDLE`、`RUNNING` 或 `FINISHED` |
| `hybridclr_dump_result()` | 查询最近结果，运行中返回 `BUSY` |
| `hybridclr_dump_cancel()` | 请求协作式取消，不强行中断 native 调用 |

一次仅允许一个采集，完成后可再次调用。异步采集必须保持 gate，直到状态为 `HYBRIDCLR_DUMP_FINISHED`，再读取结果。线程附加由库处理，只分离自己创建的附加。**保持 SO 加载，不要用 `FINISHED` 作为 `dlclose` 的安全屏障。**

### 外部注入自动启动

1. 使用 `HYBRIDCLR_DUMPER_AUTOSTART=ON` 构建，选择严格 gate 配置或明确的无 gate 实验配置。
2. 将配置安装为 `/data/user/<user>/<package>/files/hybridclr_dump.conf`，确保应用可读；默认输出位于同一 `files` 目录下。
3. 等待目标应用完成相关 DLL 加载，通过外部注入器向目标 PID 加载 SO；项目不提供注入器命令。
4. 及时恢复目标线程，避免暂停持有运行时锁的线程。严格模式的应用 gate 必须保持到采集完成。
5. 使用 `adb logcat -s HybridCLRDump` 查看完成日志和本次会话路径，再导出整个会话目录。

构造函数仅创建 bootstrap 线程，按进程包名和 Android 用户推断配置路径；用户 0 在首选路径不存在时回退到 `/data/data/<package>/files/hybridclr_dump.conf`。缺失配置不采集，项目没有 `JNI_OnLoad`。自定义进程名、隔离 UID 或非标准数据路径应使用显式 API。

自动启动只尝试一次，不监听配置变化。重复加载同一 SO 不保证再次执行构造函数；重复采集使用 API，或在允许中断测试状态时重新启动目标进程并注入。

## 输出与结果

每次采集创建独立的 `<unix-ms>-<pid>-<sequence>` 目录，不覆盖历史输出：

```text
hybridclr_dll_dump/<session>/
    manifest.json
    hot_1_HotUpdate.dll
    aot_2_System.Core.dll
    hot_1_HotUpdate.pdb
```

文件名和数量仅为示意。`.dll` / `.pdb` 表示完整复制及受支持的结构检查通过；`.partial` 表示复制或复核未完成，`.invalid.bin` 表示全字节已保存但结构检查失败。提前拒绝的对象可能没有文件。**文件存在不等于整次采集成功**，还需检查对象关联及最终审计。重复内容通过 SHA-256 和 MVID 标记 `duplicate_of_capture_id`，仍保留独立来源记录和文件。

`manifest.json` 使用 schema 3，记录来源、身份、长度、块/整文件哈希、发现证据和失败原因。重点查看：

- `all_registered_inputs_exported`：已注册输入及请求的 PDB 的导出、关联检查汇总，不能单独作为最终成功证明。
- `semantic_evidence_unchanged`：auto 的最终语义证据复核是否通过。
- `experimental_ungated_capture`：是否缺少声明的真实 gate。
- `complete_within_declared_scope`：声明范围内是否完整；无 gate 时始终为 `false`。

同时检查 `result_code`、`cancelled` 和各候选状态；最终审计中取消或异常时，先前的导出汇总标志可能仍为 `true`。

| 原生结果码 | 含义 |
| --- | --- |
| `0` | 声明范围内全部完成，真实 gate 仍是调用方前置条件 |
| `1` | 存在未完成/无效候选或文件，或本次为无 gate 实验 |
| `-1` | 选项或配置加载/校验失败 |
| `-2` | 已有采集正在运行 |
| `-3` | 全局设置、发现、运行时或报告输出失败 |
| `-4` | 协作式取消 |

## 独立校验

将完整会话拉回主机后，使用 Python 3 安装校验依赖并运行：

```powershell
python -m pip install -r verification/requirements.txt
python verification/verify_captures.py "<local-session-directory>" `
    --output "<local-session-directory>/host-verification.json"
```

校验器检查实际文件长度、块覆盖、哈希、Assembly/MVID、IL/EH 边界和资源范围，不执行托管代码。退出码 `0` 表示 `PASS`，`1` 表示校验或比较失败，`2` 表示主会话输入、依赖或输出错误。可增加 `--compare-with "<reference-session-directory>"` 比较实际 DLL 字节、元数据身份和重复数量，不比较 PDB；参考会话缺失或无效也按比较失败返回 `1`。Host `PASS` 不证明真实 gate、运行时发现重放或跨版本兼容性。

可选原生回归测试通过 `-DHYBRIDCLR_DUMPER_BUILD_TESTS=ON` 构建。具体部署和历史设备证据见以下文档，不将历史样本计数作为新目标的成功标准：

- [中文完整工作流](DLL_Dump_Workflow_CN.md)：详细构建、注入和导出步骤；其中设备辅助脚本固定了样本包名、用户 0 和默认路径，迁移时需修改。
- [语义发现验证记录](verification/PORTABLE_VALIDATION.md)：auto 和 profile 回归证据；目前记录覆盖单一目标构建，不代表跨真实框架版本验证。
- [历史 profile 验证记录](verification/DEVICE_VALIDATION.md)：旧 profile 设备会话。
