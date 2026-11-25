# Auto IL2CPP Resolver for BNM

Put `Il2CppExportOrder.hpp` and `Il2CppResolver.hpp` in includes, then put this at the top of `native-lib.cpp` above your `onloaded()` thing

```cpp
#include "Il2CppExportOrder.hpp"
#include "Il2CppResolver.hpp"
#include <BNM/Loading.hpp>
#include <android/log.h>
#include <chrono>
#include <dlfcn.h>
#include <mutex>
#include <thread>

namespace {
std::once_flag bootonce;
la::ExportResolver exportresolver;
}

static void startnative() {
    std::call_once(bootonce, [] {
        std::thread([] {
            __android_log_print(ANDROID_LOG_INFO, "NativeMod", "Loaded; waiting for libil2cpp");
            BNM::Loading::AllowLateInitHook();
            BNM::Loading::AddOnLoadedEvent(onloaded);

            auto forceload = [&](const char* tag) {
                BNM::Loading::SetMethodFinder(la::ExportResolver::find, &exportresolver);
                auto domain_get    = (void*(*)())      la::ExportResolver::find("il2cpp_domain_get",    &exportresolver);
                auto thread_attach = (void*(*)(void*)) la::ExportResolver::find("il2cpp_thread_attach", &exportresolver);
                auto thread_detach = (void (*)(void*)) la::ExportResolver::find("il2cpp_thread_detach", &exportresolver);
                void* thr = nullptr;
                if (domain_get && thread_attach) {
                    void* d = domain_get();
                    if (d) thr = thread_attach(d);
                }
                __android_log_print(ANDROID_LOG_INFO, "NativeMod", "%s; forcing immediate BNM load (il2cpp thread attached=%d)", tag, thr != nullptr);
                BNM::Loading::TrySetupByUsersFinder();
                if (thr && thread_detach) thread_detach(thr);
                __android_log_print(ANDROID_LOG_INFO, "NativeMod", "Immediate BNM load returned");
            };

            for (int i = 0; i < 120; i++) {
                void* handle = dlopen("libil2cpp.so", RTLD_NOW | RTLD_NOLOAD);
                if (handle) {
                    if (dlsym(handle, "il2cpp_init")) {
                        exportresolver.handle = handle;
                        exportresolver.methods.clear();
                        __android_log_print(ANDROID_LOG_INFO, "NativeMod", "libil2cpp has standard exports");
                        forceload("standard exports");
                        return;
                    } else {
                        if (!exportresolver.initialize(handle)) {
                            __android_log_print(ANDROID_LOG_ERROR, "NativeMod", "Resolver rejected module: %s", exportresolver.error.c_str());
                            return;
                        }
                        __android_log_print(ANDROID_LOG_INFO, "NativeMod", "Mapped %zu renamed IL2CPP exports", exportresolver.methods.size());
                        forceload("renamed exports via handle");
                        return;
                    }
                }
                if (!handle && exportresolver.initialize_loaded()) {
                    __android_log_print(ANDROID_LOG_INFO, "NativeMod", "Discovered loaded IL2CPP; mapped %zu renamed exports", exportresolver.methods.size());
                    forceload("discovered loaded IL2CPP");
                    return;
                }
                if (!handle && exportresolver.error != "libil2cpp module not visible to dl_iterate_phdr") {
                    __android_log_print(ANDROID_LOG_ERROR, "NativeMod", "Loaded module resolver rejected: %s", exportresolver.error.c_str());
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            __android_log_print(ANDROID_LOG_ERROR, "NativeMod", "libil2cpp not available in loader namespace");
        }).detach();
    });
}

__attribute__((constructor)) static void nativeentry() {
    startnative();
}
```
Also credits to ai and I have no fuggin clue if this readme actually will work or not but eh idgaf

