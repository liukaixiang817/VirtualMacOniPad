#include "modern_swift_vmm_reserve_capacity_identity.h"
#include "reserve-capacity-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <limits.h>

namespace {
bool Read(const void *p, void *d, size_t n) {
  vm_size_t copied = 0;
  return p && n <= 65536 && vm_read_overwrite(mach_task_self(),
    reinterpret_cast<vm_address_t>(p), n, reinterpret_cast<vm_address_t>(d),
    &copied) == KERN_SUCCESS && copied == n;
}
bool UUID(const void *p, const char *expected) {
  mach_header_64 h{};
  if (!Read(p, &h, sizeof(h)) || h.magic != MH_MAGIC_64 ||
      h.cputype != CPU_TYPE_ARM64 || h.cpusubtype != static_cast<cpu_subtype_t>(0x80000002) ||
      !h.ncmds || h.ncmds > 1024 || h.sizeofcmds > 65536) return false;
  const auto *at = static_cast<const unsigned char *>(p) + sizeof(h);
  const auto *end = at + h.sizeofcmds;
  unsigned count = 0;
  char uuid[33]{};
  for (unsigned i = 0; i < h.ncmds; ++i) {
    load_command c{};
    if (end - at < 8 || !Read(at, &c, 8) || c.cmdsize < 8 ||
        c.cmdsize % 8 || c.cmdsize > static_cast<size_t>(end - at)) return false;
    if (c.cmd == LC_UUID) {
      uuid_command u{};
      if (c.cmdsize != sizeof(u) || !Read(at, &u, sizeof(u))) return false;
      for (unsigned j = 0; j < 16; ++j) std::snprintf(uuid + j * 2, 3, "%02x", u.uuid[j]);
      ++count;
    }
    at += c.cmdsize;
  }
  return at == end && count == 1 && !std::strcmp(uuid, expected);
}
bool File(const char *path, uint64_t bytes, const char *expected) {
  struct stat st{};
  if (lstat(path, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
      st.st_size < 0 || static_cast<uint64_t>(st.st_size) != bytes ||
      (st.st_mode & 0022)) return false;
  FILE *file = std::fopen(path, "rb");
  if (!file) return false;
  CC_SHA256_CTX state{}; CC_SHA256_Init(&state);
  unsigned char chunk[4096], digest[32]; uint64_t total = 0;
  size_t n = 0;
  while ((n = std::fread(chunk, 1, sizeof(chunk), file))) {
    total += n; CC_SHA256_Update(&state, chunk, static_cast<CC_LONG>(n));
  }
  bool okay = !std::ferror(file) && total == bytes;
  if (std::fclose(file)) okay = false;
  CC_SHA256_Final(digest, &state);
  char hex[65]{};
  for (unsigned i = 0; i < 32; ++i) std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
  return okay && !std::strcmp(hex, expected);
}
int Identity(const char *phase) {
  char self[PATH_MAX]{}, executable[PATH_MAX]{}, root[PATH_MAX]{};
  uint32_t length = sizeof(self);
  if (_NSGetExecutablePath(self, &length) || !realpath(self, executable)) return 0;
  std::strcpy(root, executable);
  auto *slash = std::strrchr(root, '/'); if (!slash) return 0; *slash = 0;
  const void *bases[2]{}; int count = 0;
  for (unsigned index = 0; index < 2; ++index) {
    const auto& pin = ProviderPins[index];
    char expected[PATH_MAX]{}, actual[PATH_MAX]{};
    int size = std::snprintf(expected, sizeof(expected), "%s/%s/%s", root, RoleDirectory, pin.file);
    if (size < 0 || static_cast<size_t>(size) >= sizeof(expected) ||
        !realpath(expected, actual) || !File(actual, pin.bytes, pin.sha)) return 0;
    void *handle = dlopen(actual, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    if (!handle) return 0;
    bool okay = true;
    for (const auto& entry : EntryPins) {
      if (entry.provider != index) continue;
      void *function = dlsym(handle, entry.name);
      const void *code = ptrauth_strip(function, ptrauth_key_function_pointer);
      Dl_info info{}; char owner[PATH_MAX]{};
      if (!function || !dladdr(code, &info) || !info.dli_fname ||
          !realpath(info.dli_fname, owner) || std::strcmp(owner, actual) ||
          !UUID(info.dli_fbase, pin.uuid) ||
          (bases[index] && bases[index] != info.dli_fbase) ||
          reinterpret_cast<uintptr_t>(code) - reinterpret_cast<uintptr_t>(info.dli_fbase) != entry.rva) {
        okay = false; break;
      }
      bases[index] = info.dli_fbase; ++count;
    }
    if (dlclose(handle) || !okay) return 0;
    std::printf("{\"record\":\"provider\",\"phase\":\"%s\",\"index\":%u,\"UUID\":\"%s\",\"fileSHA256\":\"%s\",\"exactFile\":true,\"exactOwnerAndRVA\":true}\n",
      phase, index, pin.uuid, pin.sha);
  }
  // Self hash is supplied by the real parent as an argument after signing,
  // avoiding a recursive embedded-hash fiction.
  const char *expectedSelf = std::getenv("VM27_PROBE_SHA256");
  const char *expectedBytes = std::getenv("VM27_PROBE_BYTES");
  if (!expectedSelf || std::strlen(expectedSelf) != 64 || !expectedBytes) return 0;
  char *last = nullptr; auto bytes = std::strtoull(expectedBytes, &last, 10);
  if (!last || *last || !bytes || !File(executable, bytes, expectedSelf)) return 0;
  std::printf("{\"record\":\"identity\",\"phase\":\"%s\",\"entries\":%d,\"selfFileExact\":true,\"entryCallsDuringIdentity\":0}\n", phase, count);
  std::fflush(stdout); return count == 9 ? count : 0;
}
}

extern "C" int VM27VMMReserveStart() {
  rlimit cpu{5, 6}, core{0, 0};
  if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) return 0;
  alarm(10);
  std::printf("{\"record\":\"start\",\"PID\":%d,\"VMCalls\":0,\"GPUCalls\":0,\"diskCalls\":0,\"CPUsoft\":5,\"CPUhard\":6,\"wallSeconds\":10}\n", getpid());
  return Identity("before");
}
extern "C" int VM27VMMReserveFinish() { return Identity("after"); }
