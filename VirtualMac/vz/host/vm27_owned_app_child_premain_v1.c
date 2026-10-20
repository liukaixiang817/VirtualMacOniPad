#include "vm27_owned_app_child_startup_v1.h"
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* This unit belongs only to the original child executable's dependency graph.
 * It must never be included in the frontend loadOrder. The adapter library
 * contains no constructor; frontend loading it cannot run this child entry. */
static VM27OwnedAppChildV1 *ActualChildStartupOwnerV1;
static bool ActualOriginalChildV1(void) {
 const struct mach_header_64 *h=(const void *)_dyld_get_image_header(0);
 if(!h || h->magic!=MH_MAGIC_64 || h->filetype!=MH_EXECUTE || (uint32_t)h->cputype!=0x100000c ||
  !h->ncmds || h->ncmds>512 || h->sizeofcmds>1024*1024)return false;
 static const uint8_t uuid[16]={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
 const uint8_t *at=(const uint8_t *)(h+1),*end=at+h->sizeofcmds;bool found=false;
 for(uint32_t i=0;i<h->ncmds;i++) {
  if((size_t)(end-at)<8)return false;const struct load_command *c=(const void *)at;
  if(c->cmdsize<8 || c->cmdsize&7 || c->cmdsize>(size_t)(end-at))return false;
  if(c->cmd==LC_UUID){if(found || c->cmdsize!=24 || memcmp(at+8,uuid,16))return false;found=true;}
  at+=c->cmdsize;
 }
 return found && at==end;
}
__attribute__((constructor)) static void ActualOwnedChildPreMainV1(void) {
 /* UUID is a role boundary, never permission. The actual parent subsequently
  * admits this child's signed full file and kernel CD via typed Large2 before
  * releasing any configuration. The child itself authenticates getppid's real
  * token/CD/CS_VALID/dual native Booleans before V3 preparation or original Main. */
 if(!ActualOriginalChildV1() || VM27OwnedAppChildBootstrapBeforeMainV2(&ActualChildStartupOwnerV1))_exit(78);
 /* Keep the true owner/control connection for original Main's process lifetime.
  * No NativeOps installation, native VM/CPU operation or system mutation here. */
}
