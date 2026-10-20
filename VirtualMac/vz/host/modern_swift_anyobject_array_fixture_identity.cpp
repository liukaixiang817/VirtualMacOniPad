#include "modern_swift_anyobject_array_fixture_identity.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits.h>

#ifndef VM27_ARRAY_LIBRARY_UUID
#error "Builder must pin the actual provider UUID"
#endif
#ifndef VM27_ARRAY_LIBRARY_SUBDIR
#error "Builder must pin the exact sibling provider directory"
#endif

namespace {
const char *Names[] = {
  "$sSa034_makeUniqueAndReserveCapacityIfNotB0yyFyXl_Ts5",
  "$sSa16_createNewBuffer14bufferIsUnique15minimumCapacity13growForAppendySb_SiSbtFyXl_Ts5",
  "$sSa37_appendElementAssumeUniqueAndCapacity_03newB0ySi_xntFyXl_Ts5",
  "$ss12_ArrayBufferV19_getElementSlowPathyyXlSiFyXl_Ts5",
  "$ss15ContiguousArrayV034_makeUniqueAndReserveCapacityIfNotD0yyFyXl_Ts5",
  "$ss15ContiguousArrayV12_endMutationyyFyXl_Ts5",
  "$ss15ContiguousArrayV36_reserveCapacityAssumingUniqueBuffer8oldCountySi_tFyXl_Ts5",
  "$ss15ContiguousArrayV37_appendElementAssumeUniqueAndCapacity_03newD0ySi_xntFyXl_Ts5"
};
bool Read(const void *p, void *d, size_t n) {
  vm_size_t got = 0;
  return p && n <= 65536 && vm_read_overwrite(mach_task_self(),
    (vm_address_t)p, n, (vm_address_t)d, &got) == KERN_SUCCESS && got == n;
}
bool UUID(const void *p, char uuid[33]) {
  mach_header_64 h{};
  if (!Read(p, &h, sizeof(h)) || h.magic != MH_MAGIC_64 ||
      h.cputype != CPU_TYPE_ARM64 || h.cpusubtype != (cpu_subtype_t)0x80000002 ||
      !h.ncmds || h.ncmds > 1024 || h.sizeofcmds > 65536) return false;
  const auto *at = (const unsigned char *)p + sizeof(h);
  const auto *end = at + h.sizeofcmds;
  unsigned count = 0;
  for (unsigned i = 0; i < h.ncmds; ++i) {
    load_command c{};
    if (end - at < 8 || !Read(at, &c, 8) || c.cmdsize < 8 ||
        c.cmdsize % 8 || c.cmdsize > size_t(end - at)) return false;
    if (c.cmd == LC_UUID) {
      uuid_command u{};
      if (c.cmdsize != sizeof(u) || !Read(at, &u, sizeof(u))) return false;
      for (unsigned j = 0; j < 16; ++j) std::snprintf(uuid + j*2, 3, "%02x", u.uuid[j]);
      ++count;
    }
    at += c.cmdsize;
  }
  return at == end && count == 1 && !std::strcmp(uuid, VM27_ARRAY_LIBRARY_UUID);
}
}

extern "C" int VM27ArrayProviderIdentity(void) {
  char executable[PATH_MAX]{}, expected[PATH_MAX]{}, actual[PATH_MAX]{};
  uint32_t n = sizeof(executable);
  if (_NSGetExecutablePath(executable, &n) || !realpath(executable, actual)) return 0;
  auto *slash = std::strrchr(actual, '/');
  if (!slash) return 0;
  *slash = 0;
  int length = std::snprintf(expected, sizeof(expected), "%s/%s/VM27AnyObjectArray.dylib",
                            actual, VM27_ARRAY_LIBRARY_SUBDIR);
  if (length < 0 || size_t(length) >= sizeof(expected) || !realpath(expected, executable)) return 0;
  void *handle = dlopen(executable, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  if (!handle) return 0;
  const void *base = nullptr;
  char uuid[33]{};
  int count = 0;
  for (const char *name : Names) {
    const void *entry = dlsym(handle, name);
    Dl_info info{};
    const void *code = ptrauth_strip(entry, ptrauth_key_function_pointer);
    if (!entry || !dladdr(code, &info) || !info.dli_fname ||
        !realpath(info.dli_fname, actual) || std::strcmp(actual, executable) ||
        !UUID(info.dli_fbase, uuid) || (base && base != info.dli_fbase)) break;
    base = info.dli_fbase;
    ++count;
  }
  const int closed = dlclose(handle);
  if (closed || count != 8) return 0;
  std::printf("{\"runtimeProviderUUID\":\"%s\",\"runtimeEntryIdentities\":8,"
              "\"providerPath\":\"%s\",\"SwiftEntryCallsDuringIdentity\":0}\n", uuid, executable);
  return count;
}
