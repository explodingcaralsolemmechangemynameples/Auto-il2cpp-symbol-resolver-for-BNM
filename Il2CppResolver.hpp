#pragma once
#include "Il2CppExportOrder.hpp"
#include <link.h>
#include <elf.h>
#include <dlfcn.h>
#include <android/log.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>
namespace la {
struct ExportResolver {
    struct Range { uintptr_t first,last; unsigned flags; };
    std::vector<Range> ranges;
    std::unordered_map<std::string,void*> methods;
    uintptr_t bias=0, anchor=0;
    std::string error;
    static constexpr size_t limit=262144;
    bool inside(uintptr_t p,size_t size,unsigned flags=PF_R) const {
        for(auto r:ranges) if((r.flags&flags)==flags && p>=r.first && p<=r.last && size<=r.last-p) return true;
        return false;
    }
    uintptr_t relocate(uintptr_t p) const {
        if(inside(p,1)) return p;
        return p<=UINTPTR_MAX-bias && inside(bias+p,1)?bias+p:0;
    }
    bool reject(const char* why) {error=why;return false;}
    bool inspect(const dl_phdr_info& info) {
        bias=info.dlpi_addr; ranges.clear();
        const ElfW(Phdr)* dynamic=nullptr;
        for(size_t i=0;i<info.dlpi_phnum;i++) {
            const auto& p=info.dlpi_phdr[i];
            if(p.p_vaddr>UINTPTR_MAX-bias || p.p_memsz>UINTPTR_MAX-(bias+p.p_vaddr)) return reject("ELF range overflow");
            if(p.p_type==PT_LOAD) ranges.push_back({bias+p.p_vaddr,bias+p.p_vaddr+p.p_memsz,p.p_flags});
            if(p.p_type==PT_DYNAMIC) dynamic=&p;
        }

        if(!dynamic || !inside(bias+dynamic->p_vaddr,dynamic->p_memsz)) return reject("Missing readable PT_DYNAMIC");
        uintptr_t sym=0,str=0,hash=0,gnu=0;size_t strsize=0,syment=0;
        auto* d=reinterpret_cast<const ElfW(Dyn)*>(bias+dynamic->p_vaddr);
        bool ended=false;
        for(size_t i=0;i<dynamic->p_memsz/sizeof(*d);i++) {
            if(d[i].d_tag==DT_NULL){ended=true;break;}
            switch(d[i].d_tag) {
                case DT_SYMTAB:sym=relocate(d[i].d_un.d_ptr);break;
                case DT_STRTAB:str=relocate(d[i].d_un.d_ptr);break;
                case DT_STRSZ:strsize=d[i].d_un.d_val;break;
                case DT_SYMENT:syment=d[i].d_un.d_val;break;
                case DT_HASH:hash=relocate(d[i].d_un.d_ptr);break;
                case DT_GNU_HASH:gnu=relocate(d[i].d_un.d_ptr);break;
            }
        }
        if(!ended || !sym || !str || syment!=sizeof(ElfW(Sym)) || !inside(str,strsize)) return reject("Invalid dynamic symbol/string table");
        size_t count=0;
        if(hash && inside(hash,8)) count=reinterpret_cast<const uint32_t*>(hash)[1];
        else if(gnu && inside(gnu,16)) {
            auto* h=reinterpret_cast<const uint32_t*>(gnu);
            size_t buckets=h[0],first=h[1],bloom=h[2];
            if(!buckets || buckets>limit || bloom>limit || first>limit) return reject("Invalid GNU hash header");
            uintptr_t bucket=gnu+16+bloom*sizeof(ElfW(Addr));
            if(!inside(bucket,buckets*4)) return reject("Invalid GNU hash buckets");
            auto* b=reinterpret_cast<const uint32_t*>(bucket);size_t last=0;
            for(size_t i=0;i<buckets;i++) last=std::max(last,static_cast<size_t>(b[i]));
            if(last==0) count=first;
            else {
                if(last<first || last>=limit) return reject("Invalid GNU hash index");
                uintptr_t chains=bucket+buckets*4;
                for(;last<limit;last++) {
                    uintptr_t at=chains+(last-first)*4;
                    if(!inside(at,4)) return reject("Truncated GNU hash chain");
                    if(*reinterpret_cast<const uint32_t*>(at)&1){count=last+1;break;}
                }
            }
        }
        if(!count || count>limit || !inside(sym,count*sizeof(ElfW(Sym)))) return reject("Unbounded dynamic symbol count");
        auto* symbols=reinterpret_cast<const ElfW(Sym)*>(sym);
        // Prefer real names throughout the module, independent of anchor interval.
        std::unordered_map<std::string,void*> named;
        for(size_t i=0;i<count;i++) {
            const auto& e=symbols[i];
            unsigned bind=ELF64_ST_BIND(e.st_info), visibility=e.st_other&3;
            if(e.st_shndx==SHN_UNDEF || (bind!=STB_GLOBAL && bind!=STB_WEAK) ||
               (visibility!=STV_DEFAULT && visibility!=STV_PROTECTED) || e.st_name>=strsize)continue;
            const char* label=reinterpret_cast<const char*>(str+e.st_name);
            if(!memchr(label,0,strsize-e.st_name))return reject("Unterminated named export");
            uintptr_t address=e.st_shndx==SHN_ABS?e.st_value:bias+e.st_value;
            if(strncmp(label,"il2cpp_",7) || ELF64_ST_TYPE(e.st_info)!=STT_FUNC || address%4 || !inside(address,4,PF_X))continue;
            auto [it,inserted]=named.emplace(label,reinterpret_cast<void*>(address));
            if(!inserted && it->second!=reinterpret_cast<void*>(address))return reject("Ambiguous exact IL2CPP export");
        }
        // Real (un-obfuscated) names: accept them even if this Unity build adds or
        // drops a few exports compared to export_order. Renamed builds expose almost
        // no il2cpp_* names, so they still fall through to the ordering heuristic.
        size_t missing=0; std::string missingnames;
        for(auto canonical:export_order) if(!named.contains(std::string(canonical))) {
            ++missing; if(missingnames.size()<400) {missingnames+=' ';missingnames+=canonical;}
        }
        if(missing==0 || (named.size()>=export_order.size()/2 && missing<=export_order.size()/10)) {
            if(missing) __android_log_print(ANDROID_LOG_WARN,"UniversalImGui","Using %zu named il2cpp exports; %zu expected ones absent:%s",named.size(),missing,missingnames.c_str());
            methods=std::move(named);return true;
        }
        uintptr_t end=0; anchor=0;
        for(size_t i=0;i<count;i++) {
            const auto& e=symbols[i];
            if(e.st_shndx==SHN_UNDEF || e.st_name>=strsize)continue;
            const char* label=reinterpret_cast<const char*>(str+e.st_name);
            if(!memchr(label,0,strsize-e.st_name))return reject("Unterminated boundary name");
            if(!strcmp(label,"UnityAdsEngineSetDidFinishCallback"))anchor=bias+e.st_value;
            if(!strcmp(label,"CreateZStream"))end=bias+e.st_value;
        }
        if(!anchor || !end || anchor>=end || !inside(anchor,4,PF_X) || !inside(end,4,PF_X))return reject("Invalid export boundary symbols");
        std::vector<uintptr_t> ordered;
        for(size_t i=0;i<count;i++) {
            auto& entry=symbols[i];
            unsigned bind=ELF64_ST_BIND(entry.st_info), visibility=(entry.st_other & 3);
            if(entry.st_shndx==SHN_UNDEF || (bind!=STB_GLOBAL && bind!=STB_WEAK) || (visibility!=STV_DEFAULT && visibility!=STV_PROTECTED)) continue;
            if(entry.st_name>=strsize) return reject("Invalid export string offset");
            const char* label=reinterpret_cast<const char*>(str+entry.st_name);
            if(!memchr(label,0,strsize-entry.st_name)) return reject("Unterminated export name");
            uintptr_t value=entry.st_shndx==SHN_ABS?entry.st_value:bias+entry.st_value;
            if(value>anchor && value<end) {
                if(!inside(value,4,PF_X) || value%4) return reject("Non-function export inside API interval");
                ordered.push_back(value);
            }
        }
        std::sort(ordered.begin(),ordered.end());
        if(std::adjacent_find(ordered.begin(),ordered.end())!=ordered.end()) return reject("Aliased export addresses make ordering ambiguous");

        // Unity versions differ by a few optional exports. Build every candidate
        // order (base list + a subset of the optional ones at their fixed spots)
        // whose length matches, then pick the one whose code fingerprints line up.
        struct optional_export { const char* name; const char* after; };
        static constexpr optional_export optionals[]={
            {"il2cpp_assembly_get_object","il2cpp_assembly_get_image"},
            {"il2cpp_gc_is_heap_ptr",     "il2cpp_gc_free_fixed"},
        };
        constexpr size_t nopt=sizeof(optionals)/sizeof(optionals[0]);
        auto buildorder=[&](unsigned mask){
            std::vector<std::string_view> o;
            for(auto n:export_order) {
                o.push_back(n);
                for(size_t k=0;k<nopt;k++) if((mask>>k)&1 && n==optionals[k].after) o.push_back(optionals[k].name);
            }
            return o;
        };
        // Follow one obfuscator thunk ("b target") to the real body.
        auto body=[&](uintptr_t p)->const uint32_t* {
            for(int hop=0;hop<2;hop++) {
                if(!inside(p,8,PF_X)) return nullptr;
                uint32_t ins=*reinterpret_cast<const uint32_t*>(p);
                if((ins&0xFC000000u)!=0x14000000u) break;
                int64_t off=static_cast<int64_t>(static_cast<int32_t>(ins<<6)>>6)*4;
                p=static_cast<uintptr_t>(static_cast<int64_t>(p)+off);
            }
            return inside(p,8,PF_X)?reinterpret_cast<const uint32_t*>(p):nullptr;
        };
        auto score=[&](const std::vector<std::string_view>& o){
            int s=0;
            for(size_t i=0;i<o.size();i++) {
                const uint32_t* b=body(ordered[i]); if(!b) continue;
                if(o[i]=="il2cpp_assembly_get_image" && b[0]==0xF9400000u && b[1]==0xD65F03C0u) s+=2; // ldr x0,[x0]; ret
                if(o[i]=="il2cpp_gchandle_new"       && b[0]==0xAA0003E8u && b[1]==0x52800049u) s+=2; // mov x8,x0; mov w9,#2
                if(o[i]=="il2cpp_gc_is_heap_ptr"     && (b[1]&0xFC000000u)==0x94000000u) s+=1;        // bl helper; ...
                if(o[i]=="il2cpp_class_enum_basetype"&& (b[0]&0xFFC003FFu)==0xF9400008u && b[1]==0x91008100u) s+=2; // ldr x8,[x0,#k]; add x0,x8,#0x20
            }
            return s;
        };
        int bestscore=-1; unsigned bestmask=0; int ties=0;
        for(unsigned mask=0;mask<(1u<<nopt);mask++) {
            auto o=buildorder(mask);
            if(o.size()!=ordered.size()) continue;
            int sc=score(o);
            if(sc>bestscore) {bestscore=sc;bestmask=mask;ties=0;}
            else if(sc==bestscore) ties++;
        }
        std::vector<std::string_view> o;
        if(bestscore<0) {
            // Unknown layout: map positionally like tuff.js (first N in address order),
            // never refuse. Pick whichever candidate list is closest in length.
            unsigned closest=0; size_t bestdiff=SIZE_MAX;
            for(unsigned mask=0;mask<(1u<<nopt);mask++) {
                size_t n=buildorder(mask).size(), d=n>ordered.size()?n-ordered.size():ordered.size()-n;
                if(d<bestdiff) {bestdiff=d;closest=mask;}
            }
            bestmask=closest; o=buildorder(closest);
            __android_log_print(ANDROID_LOG_WARN,"UniversalImGui","Export count %zu matches no known layout (base %zu); mapping positionally",
                                ordered.size(),export_order.size());
        } else {
            if(ties) __android_log_print(ANDROID_LOG_WARN,"UniversalImGui","Export layout tie (score %d); using first best",bestscore);
            o=buildorder(bestmask);
        }
        size_t n=std::min(o.size(),ordered.size());
        for(size_t i=0;i<n;i++) methods.emplace(std::string(o[i]),reinterpret_cast<void*>(ordered[i]));
        std::string extra;
        for(size_t k=0;k<nopt;k++) if((bestmask>>k)&1) {extra+=' ';extra+=optionals[k].name;}
        __android_log_print(ANDROID_LOG_INFO,"UniversalImGui","Positional export map: %zu exports, fingerprint score %d, optional:%s",
                            n,bestscore,extra.empty()?" none":extra.c_str());
        return true;
    }
    bool initialize_loaded() {
        methods.clear();ranges.clear();error.clear();handle=nullptr;
        struct Search {ExportResolver* self;bool found=false;bool ok=false;} search{this};
        dl_iterate_phdr([](dl_phdr_info* info,size_t,void* arg)->int {
            auto& search=*static_cast<Search*>(arg);
            if(!info->dlpi_name)return 0;
            std::string path=info->dlpi_name;
            constexpr const char suffix[]="/libil2cpp.so";
            if(path!="libil2cpp.so" && (path.size()<sizeof(suffix)-1 || path.compare(path.size()-(sizeof(suffix)-1),sizeof(suffix)-1,suffix)))return 0;
            search.found=true;search.ok=search.self->inspect(*info);return 1;
        },&search);
        if(!search.found)return reject("libil2cpp module not visible to dl_iterate_phdr");
        return search.ok;
    }
    void* handle=nullptr;
    bool initialize(void* library) {
        handle=library; methods.clear();error.clear();
        anchor=reinterpret_cast<uintptr_t>(dlsym(handle,"UnityAdsEngineSetDidFinishCallback"));
        if(!anchor)return reject("Start boundary export missing");
        struct Search { ExportResolver* self; bool found=false;bool ok=false; } search{this};
        dl_iterate_phdr([](dl_phdr_info* info,size_t,void* arg)->int {
            auto& search=*static_cast<Search*>(arg);
            for(size_t i=0;i<info->dlpi_phnum;i++) {
                const auto& p=info->dlpi_phdr[i];
                if(p.p_type!=PT_LOAD)continue;
                uintptr_t begin=info->dlpi_addr+p.p_vaddr;
                if(search.self->anchor>=begin && search.self->anchor-begin<p.p_memsz) {
                    search.found=true;search.ok=search.self->inspect(*info);return 1;
                }
            }
            return 0;
        },&search);
        if(!search.found)return reject("Boundary address not in a loaded ELF module");
        return search.ok;
    }
    static void* find(const char* name,void* data) {
        auto& self=*static_cast<ExportResolver*>(data);
        if(!name)return nullptr;
        auto it=self.methods.find(name);
        if(it!=self.methods.end())return it->second;
        return self.handle ? dlsym(self.handle,name) : nullptr;
    }
};
}

