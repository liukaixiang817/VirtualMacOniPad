/* A one-shot record for this owned VMM only. No attempt to recover from a
 * fault: restore the original default disposition and terminate with SIGSEGV.
 * The register words are raw data, never authenticated, stripped or executed. */
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <unistd.h>
#include <fcntl.h>

static const char VM27FatalPathV2[] =
 "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/"
 "VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/"
 "Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static uintptr_t VM27FatalBaseV2;
static struct sigaction VM27FatalPreviousV2;

/* Pure bounded formatting; no allocation, locks, Objective-C, unwinding,
 * arbitrary stack reads or symbol lookup in the signal handler. */
static size_t VM27FatalTextV2(char *out, size_t used, const char *s) {
 while (*s && used < 1000) out[used++] = *s++;
 return used;
}
static size_t VM27FatalHexV2(char *out, size_t used, uint64_t value) {
 static const char digits[] = "0123456789abcdef";
 if (used > 982) return used;
 out[used++] = '0'; out[used++] = 'x';
 for (unsigned i = 0; i < 16; ++i)
  out[used++] = digits[(value >> (60 - i * 4)) & 15];
 return used;
}
static uint64_t VM27FatalWordV2(const volatile unsigned char *p) {
 uint64_t value = 0;
 for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
 return value;
}
static void VM27FatalHandlerV2(int number, siginfo_t *info, void *context) {
 char record[1024]; size_t used = 0;
 /* Only the default disposition is admitted at installation. Reset first,
  * including on diagnostic failure; another fault cannot recurse here. */
 int restored = sigaction(SIGSEGV, &VM27FatalPreviousV2, NULL);
 used = VM27FatalTextV2(record, used, "[VM27OwnedVMMFatalContextV2] signal=SIGSEGV rawRegisters=1 recoverExecution=0 base=");
 used = VM27FatalHexV2(record, used, VM27FatalBaseV2);
 used = VM27FatalTextV2(record, used, " address=");
 used = VM27FatalHexV2(record, used, info ? (uintptr_t)info->si_addr : 0);
 ucontext_t *uc = (ucontext_t *)context;
 if (uc && uc->uc_mcontext) {
  const volatile unsigned char *state =
   (const volatile unsigned char *)&uc->uc_mcontext->__ss;
  /* Darwin arm64 thread-state ABI: x[29], fp, lr, sp, pc, cpsr, flags.
   * Byte reads also preserve opaque arm64e PAC values without accessors. */
  _Static_assert(sizeof(uc->uc_mcontext->__ss) == 272, "Darwin ARM64 thread state");
  static const char *const names[] = {" x0=", " x1=", " x2=", " x3=",
   " x4=", " x5=", " x6=", " x7=", " fp=", " lr=", " sp=", " pc="};
  static const unsigned offsets[] = {0,8,16,24,32,40,48,56,232,240,248,256};
  for (unsigned i = 0; i < 12; ++i) {
   used = VM27FatalTextV2(record, used, names[i]);
   used = VM27FatalHexV2(record, used, VM27FatalWordV2(state + offsets[i]));
  }
  used = VM27FatalTextV2(record, used, " esr=");
  used = VM27FatalHexV2(record, used, uc->uc_mcontext->__es.__esr);
  used = VM27FatalTextV2(record, used, " far=");
  used = VM27FatalHexV2(record, used, uc->uc_mcontext->__es.__far);
 }
 used = VM27FatalTextV2(record, used,
  restored == 0 ? " defaultDispositionRestored=1\n" : " defaultDispositionRestored=0\n");
 (void)write(STDERR_FILENO, record, used); /* At most one <=1000-byte write. */
 if (restored == 0) {
  sigset_t unblocked;
  sigemptyset(&unblocked); sigaddset(&unblocked, number);
  (void)sigprocmask(SIG_UNBLOCK, &unblocked, NULL);
  (void)kill(getpid(), number);
 }
 _exit(128 + number); /* Own-process fail-closed fallback, never resume. */
}

__attribute__((constructor)) static void VM27InstallFatalContextV2(void) {
 char path[4096] = {0}, logPath[4096] = {0}; uint32_t pathSize = sizeof(path); struct stat log;
 if (getuid() != 501 || geteuid() != 501 ||
     _NSGetExecutablePath(path, &pathSize) != 0 ||
     strcmp(path, VM27FatalPathV2) != 0 || fstat(STDERR_FILENO, &log) ||
     !S_ISREG(log.st_mode) || log.st_uid != 501 || log.st_gid != 501 ||
     (log.st_mode & 07777) != 0600 || log.st_nlink != 1 ||
     fcntl(STDERR_FILENO, F_GETPATH, logPath) ||
     (strcmp(logPath,"/tmp/VirtualMacIndependent27.log") &&
      strcmp(logPath,"/private/tmp/VirtualMacIndependent27.log") &&
      strcmp(logPath,"/var/tmp/VirtualMacIndependent27.log") &&
      strcmp(logPath,"/private/var/tmp/VirtualMacIndependent27.log")))
  return;
 unsigned found = 0;
 for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
  const char *name = _dyld_get_image_name(i);
  if (name && strcmp(name, VM27FatalPathV2) == 0) {
   const struct mach_header *header = _dyld_get_image_header(i);
   if (!header || header->magic != MH_MAGIC_64 || header->filetype != MH_EXECUTE)
    return;
   VM27FatalBaseV2 = (uintptr_t)header; ++found;
  }
 }
 for(uint32_t i=0;i<_dyld_image_count();++i) {
  const char *name=_dyld_get_image_name(i);if(!name)continue;
  const char *leaf=name;for(const char *p=name;*p;++p)if(*p=='/')leaf=p+1;
  if(strcmp(leaf,"MD") && strcmp(leaf,"ParavirtualizedGraphics27.dylib") &&
     strcmp(leaf,"com.apple.Virtualization.VirtualMachine") && strcmp(leaf,"libsystem_kernel.dylib") &&
     strcmp(leaf,"libobjc.A.dylib") && strcmp(leaf,"IOKit") && strcmp(leaf,"CoreFoundation"))continue;
  dprintf(2,"[VM27OwnedVMMFatalImageV2] base=0x%lx image=%s\n",(unsigned long)_dyld_get_image_header(i),leaf);
 }
 if (found != 1 || sigaction(SIGSEGV, NULL, &VM27FatalPreviousV2) ||
     VM27FatalPreviousV2.sa_handler != SIG_DFL) return;
 struct sigaction action = {0};
 action.sa_sigaction = VM27FatalHandlerV2;
 action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
 sigemptyset(&action.sa_mask);
 if (sigaction(SIGSEGV, &action, NULL) == 0) {
  static const char ready[] =
   "[VM27OwnedVMMFatalContextV2] installed=1 ownedVMMOnly=1 originalDefaultDisposition=1 oneShot=1 nativeCPUOrGuestStateChanges=0\n";
  (void)write(STDERR_FILENO, ready, sizeof(ready) - 1);
 }
}
