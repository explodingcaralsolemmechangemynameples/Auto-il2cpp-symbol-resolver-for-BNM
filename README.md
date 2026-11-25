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
std::once\_flag bootonce;
la::ExportResolver exportresolver;
}

static void startnative() {
    std::call\_once(bootonce, \[] {
        std::thread(\[] {
            \_\_android\_log\_print(ANDROID\_LOG\_INFO, "NativeMod", "Loaded; waiting for libil2cpp");
            BNM::Loading::AllowLateInitHook();
            BNM::Loading::AddOnLoadedEvent(onloaded);

            auto forceload = \[\&](const char\* tag) {
                BNM::Loading::SetMethodFinder(la::ExportResolver::find, \&exportresolver);
                auto domain\_get    = (void\*(\*)())      la::ExportResolver::find("il2cpp\_domain\_get",    \&exportresolver);
                auto thread\_attach = (void\*(\*)(void\*)) la::ExportResolver::find("il2cpp\_thread\_attach", \&exportresolver);
                auto thread\_detach = (void (\*)(void\*)) la::ExportResolver::find("il2cpp\_thread\_detach", \&exportresolver);
                void\* thr = nullptr;
                if (domain\_get \&\& thread\_attach) {
                    void\* d = domain\_get();
                    if (d) thr = thread\_attach(d);
                }
                \_\_android\_log\_print(ANDROID\_LOG\_INFO, "NativeMod", "%s; forcing immediate BNM load (il2cpp thread attached=%d)", tag, thr != nullptr);
                BNM::Loading::TrySetupByUsersFinder();
                if (thr \&\& thread\_detach) thread\_detach(thr);
                \_\_android\_log\_print(ANDROID\_LOG\_INFO, "NativeMod", "Immediate BNM load returned");
            };

            for (int i = 0; i < 120; i++) {
                void\* handle = dlopen("libil2cpp.so", RTLD\_NOW | RTLD\_NOLOAD);
                if (handle) {
                    if (dlsym(handle, "il2cpp\_init")) {
                        exportresolver.handle = handle;
                        exportresolver.methods.clear();
                        \_\_android\_log\_print(ANDROID\_LOG\_INFO, "NativeMod", "libil2cpp has standard exports");
                        forceload("standard exports");
                        return;
                    } else {
                        if (!exportresolver.initialize(handle)) {
                            \_\_android\_log\_print(ANDROID\_LOG\_ERROR, "NativeMod", "Resolver rejected module: %s", exportresolver.error.c\_str());
                            return;
                        }
                        \_\_android\_log\_print(ANDROID\_LOG\_INFO, "NativeMod", "Mapped %zu renamed IL2CPP exports", exportresolver.methods.size());
                        forceload("renamed exports via handle");
                        return;
                    }
                }
                if (!handle \&\& exportresolver.initialize\_loaded()) {
                    \_\_android\_log\_print(ANDROID\_LOG\_INFO, "NativeMod", "Discovered loaded IL2CPP; mapped %zu renamed exports", exportresolver.methods.size());
                    forceload("discovered loaded IL2CPP");
                    return;
                }
                if (!handle \&\& exportresolver.error != "libil2cpp module not visible to dl\_iterate\_phdr") {
                    \_\_android\_log\_print(ANDROID\_LOG\_ERROR, "NativeMod", "Loaded module resolver rejected: %s", exportresolver.error.c\_str());
                    return;
                }
                std::this\_thread::sleep\_for(std::chrono::milliseconds(500));
            }
            \_\_android\_log\_print(ANDROID\_LOG\_ERROR, "NativeMod", "libil2cpp not available in loader namespace");
        }).detach();
    });
}

\_\_attribute\_\_((constructor)) static void nativeentry() {
    startnative();
}
```
Also credits to ai and I have no fuggin clue if this readme actually will work or not but eh idgaf

