#if !defined(__aarch64__)
#error "The raw fixture requires AArch64."
#endif

namespace {
// Explicit code and slots keep every inspected pointer inside this module;
// no compiler-generated virtual table, pure-virtual entry, or STP stores.
__attribute__((naked)) void raw_loader() {
    __asm__ volatile(
        "add x8, x1, x2\n"
        "str x1, [x0, #8]\n"
        "str w2, [x0, #16]\n"
        "str x8, [x0, #24]\n"
        "ret\n");
}

__attribute__((naked)) void raw_ret() {
    __asm__ volatile("ret\n");
}

using Function = void (*)();
const Function kVtable[16] = {
    raw_ret, raw_ret, raw_loader, raw_ret,
    raw_ret, raw_ret, raw_ret, raw_ret,
    raw_ret, raw_ret, raw_ret, raw_ret,
    raw_ret, raw_ret, raw_ret, raw_ret,
};
} // namespace

extern "C" __attribute__((visibility("default"))) const void* hcd_raw_fixture_vtable() {
    return kVtable;
}
