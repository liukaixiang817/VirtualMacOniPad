#include "vm27_actual_executable_image_v1.h"
#include <dlfcn.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    VM27ActualExecutableImageV1 image={0};
    int status=VM27ActualExecutableImageFindSelfV1(&image);
    if(status || image.header!=dlsym(RTLD_MAIN_ONLY,"_mh_execute_header") ||
        (const void *)image.header!=_dyld_get_image_header(image.dyldIndex))return 1;
    VM27ActualExecutableImageV1 rejected={0};
    if(!VM27ActualExecutableImageFindV1("/usr/bin/true",&rejected))return 2;
    printf("{\"passed\":true,\"actualHostDyld\":true,\"dyldIndex\":%u,\"ncmds\":%u,\"sizeofcmds\":%u,\"nativeVMOperations\":0}\n",
        image.dyldIndex,image.ncmds,image.sizeofcmds);
    return 0;
}
