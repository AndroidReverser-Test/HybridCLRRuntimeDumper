#include "hybridclr_dumper.h"
#include "config.h"
#include "internal.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>

namespace {

std::mutex run_mutex;
std::atomic<int> run_state{HYBRIDCLR_DUMP_IDLE};
std::atomic<int> run_result{HYBRIDCLR_DUMP_OK};
std::atomic<bool> run_cancelled{false};

void log_exception(const char* context, const char* detail = "unknown exception") noexcept {
    try {
        hcd::log("%s: %s", context, detail);
    } catch (...) {
        // Reporting an error must not prevent completion publication.
    }
}

template<typename Work>
void launch_worker(Work&& work) {
    struct Gate {
        std::mutex mutex;
        bool enabled = false;
    };
    auto gate = std::make_shared<Gate>();
    std::unique_lock<std::mutex> lock(gate->mutex);
    std::thread worker([gate, work = std::forward<Work>(work)]() mutable {
        {
            std::lock_guard<std::mutex> guard(gate->mutex);
            if (!gate->enabled) {
                return;
            }
        }
        work();
    });
    try {
        worker.detach();
    } catch (...) {
        // A failed launch must not start runtime or bootstrap file access.
        lock.unlock();
        worker.join();
        throw;
    }
    gate->enabled = true;
}

bool begin_run() {
    std::lock_guard<std::mutex> lock(run_mutex);
    if (run_state.load(std::memory_order_acquire) == HYBRIDCLR_DUMP_RUNNING) {
        return false;
    }
    // Cancellation uses the same lock, so a visible RUNNING cannot lose a request.
    run_cancelled.store(false, std::memory_order_relaxed);
    run_result.store(HYBRIDCLR_DUMP_BUSY, std::memory_order_relaxed);
    run_state.store(HYBRIDCLR_DUMP_RUNNING, std::memory_order_release);
    return true;
}

int finish_run(int result) noexcept {
    run_result.store(result, std::memory_order_relaxed);
    run_state.store(HYBRIDCLR_DUMP_FINISHED, std::memory_order_release);
    return result;
}

bool invalid_options(const char* reason) {
    hcd::log("Invalid dump options: %s", reason);
    return false;
}

bool copy_options(const HybridClrDumpOptions* options, hcd::Config& config) {
    if (!options || options->struct_size != sizeof(HybridClrDumpOptions) ||
        options->abi_version != HYBRIDCLR_DUMPER_ABI_VERSION) {
        return invalid_options("struct_size and abi_version must match exactly");
    }
    if (options->stable_window_confirmed > 1) {
        return invalid_options("stable_window_confirmed must be 0 or 1");
    }
    if (!options->config_path || options->config_path[0] != '/') {
        return invalid_options("config_path must be a nonempty absolute path");
    }
    std::string error;
    if (!hcd::load_config(options->config_path, config, error)) {
        return invalid_options(error.c_str());
    }
    if (config.stable_window_confirmed && options->stable_window_confirmed != 1) {
        return invalid_options("the caller must confirm the configuration's lifetime gate");
    }
    return true;
}

int execute_run(const hcd::Config& config) noexcept {
    int result = HYBRIDCLR_DUMP_ERROR;
    try {
        result = hcd::dump_runtime(config, run_cancelled);
    } catch (const std::exception& error) {
        log_exception("Runtime dump exception", error.what());
    } catch (...) {
        log_exception("Runtime dump exception");
    }
    return finish_run(result);
}

int enter_run(const HybridClrDumpOptions* options, bool asynchronous) noexcept {
    bool admitted = false;
    try {
        if (!begin_run()) {
            return HYBRIDCLR_DUMP_BUSY;
        }
        admitted = true;
        hcd::Config config;
        if (!copy_options(options, config)) {
            return finish_run(HYBRIDCLR_DUMP_INVALID_OPTIONS);
        }
        if (config.stable_window_confirmed) {
            hcd::log("Dump admitted: hold the application loading/lifetime gate until completion.");
        } else {
            hcd::log("EXPERIMENTAL ungated capture: concurrent loading/freeing can crash the process. "
                     "A complete stable snapshot cannot be certified; result will not be OK.");
        }
        hcd::log("Do not unload this SO while an API or worker is active; FINISHED is not a thread-join barrier.");
        if (asynchronous) {
            launch_worker([config = std::move(config)]() noexcept {
                execute_run(config);
            });
            // Acceptance only; the worker publishes the completion result.
            return HYBRIDCLR_DUMP_OK;
        }
        return execute_run(config);
    } catch (const std::exception& error) {
        log_exception("Dump entry exception", error.what());
    } catch (...) {
        log_exception("Dump entry exception");
    }
    return admitted ? finish_run(HYBRIDCLR_DUMP_ERROR) : HYBRIDCLR_DUMP_ERROR;
}

#if defined(HYBRIDCLR_DUMPER_AUTOSTART) && HYBRIDCLR_DUMPER_AUTOSTART == 1

using File = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

enum class ConfigPresence { present, missing, error };

ConfigPresence config_presence(const std::string& path) {
    struct stat info{};
    if (::stat(path.c_str(), &info) == 0) {
        if (!S_ISREG(info.st_mode)) {
            hcd::log("Configuration %s is not a regular file; no dump started", path.c_str());
            return ConfigPresence::error;
        }
        return ConfigPresence::present;
    }
    const int code = errno;
    if (code == ENOENT) return ConfigPresence::missing;
    hcd::log("Cannot stat configuration %s: %s; no dump started",
             path.c_str(), std::strerror(code));
    return ConfigPresence::error;
}

bool read_package_name(std::string& package) {
    File file(std::fopen("/proc/self/cmdline", "rb"), &std::fclose);
    if (!file) {
        hcd::log("Cannot open /proc/self/cmdline: %s", std::strerror(errno));
        return false;
    }
    for (;;) {
        const int c = std::fgetc(file.get());
        if (c == EOF) {
            if (std::ferror(file.get())) {
                hcd::log("Cannot read /proc/self/cmdline");
                return false;
            }
            break;
        }
        if (c == 0) {
            break;
        }
        if (package.size() == 4096) {
            hcd::log("Process name exceeds 4096 bytes");
            return false;
        }
        package.push_back(static_cast<char>(c));
    }
    const size_t suffix = package.find(':');
    if (suffix != std::string::npos) {
        package.resize(suffix);
    }
    bool component_start = true;
    for (unsigned char c : package) {
        if (c == '.') {
            if (component_start) {
                hcd::log("Invalid package name in /proc/self/cmdline");
                return false;
            }
            component_start = true;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            hcd::log("Package name must contain only ASCII letters, digits, underscores and dots");
            return false;
        }
        component_start = false;
    }
    if (component_start) {
        hcd::log("Package name is empty or has an empty component");
        return false;
    }
    return true;
}

void bootstrap() noexcept {
    try {
        hcd::log("Autostart bootstrap worker active: do not unload this SO while workers "
                 "are active; FINISHED is not a thread-join barrier.");
        std::string package;
        if (!read_package_name(package)) {
            return;
        }
        const uint64_t user = static_cast<uint64_t>(getuid()) / 100000u;
        std::string files_directory = "/data/user/" + std::to_string(user) + "/" + package + "/files";
        std::string path = files_directory + "/hybridclr_dump.conf";
        ConfigPresence status = config_presence(path);
        if (status == ConfigPresence::missing && user == 0) {
            files_directory = "/data/data/" + package + "/files";
            path = files_directory + "/hybridclr_dump.conf";
            status = config_presence(path);
        }
        if (status == ConfigPresence::missing) {
            hcd::log("No app-private hybridclr_dump.conf found for package %s, Android user %llu; "
                     "no dump started", package.c_str(), static_cast<unsigned long long>(user));
            return;
        }
        if (status != ConfigPresence::present) {
            return;
        }
        HybridClrDumpOptions options{};
        options.struct_size = sizeof(HybridClrDumpOptions);
        options.abi_version = HYBRIDCLR_DUMPER_ABI_VERSION;
        options.config_path = path.c_str();
        options.stable_window_confirmed = 1;
        const int result = enter_run(&options, false);
        hcd::log("Autostart synchronous dump returned %d", result);
    } catch (const std::exception& error) {
        log_exception("Autostart bootstrap exception", error.what());
    } catch (...) {
        log_exception("Autostart bootstrap exception");
    }
}

__attribute__((constructor)) void autostart_constructor() {
    try {
        launch_worker([]() noexcept { bootstrap(); });
    } catch (const std::exception& error) {
        log_exception("Cannot create autostart bootstrap worker", error.what());
    } catch (...) {
        log_exception("Cannot create autostart bootstrap worker");
    }
}

#endif

} // namespace

extern "C" HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_run(const HybridClrDumpOptions* options) {
    return enter_run(options, false);
}

extern "C" HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_start(const HybridClrDumpOptions* options) {
    return enter_run(options, true);
}

extern "C" HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_state(void) {
    return run_state.load(std::memory_order_acquire);
}

extern "C" HYBRIDCLR_DUMPER_EXPORT int hybridclr_dump_result(void) {
    try {
        std::lock_guard<std::mutex> lock(run_mutex);
        if (run_state.load(std::memory_order_acquire) == HYBRIDCLR_DUMP_RUNNING) {
            return HYBRIDCLR_DUMP_BUSY;
        }
        return run_result.load(std::memory_order_relaxed);
    } catch (...) {
        log_exception("Cannot query dump result", "synchronization exception");
        return HYBRIDCLR_DUMP_ERROR;
    }
}

extern "C" HYBRIDCLR_DUMPER_EXPORT void hybridclr_dump_cancel(void) {
    try {
        std::lock_guard<std::mutex> lock(run_mutex);
        if (run_state.load(std::memory_order_acquire) == HYBRIDCLR_DUMP_RUNNING) {
            run_cancelled.store(true, std::memory_order_release);
        }
    } catch (...) {
        log_exception("Cannot request dump cancellation", "synchronization exception");
    }
}
