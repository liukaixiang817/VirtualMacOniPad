#include "portable_app_v1/host/vm27_owned_application_log_v1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char directory[] = "/private/tmp/vm27-log-test-XXXXXX";
    assert(mkdtemp(directory));
    char path[1024], alias[1024];
    snprintf(path,sizeof(path),"%s/app.log",directory);
    snprintf(alias,sizeof(alias),"%s/alias",directory);
    umask(0022);
    FILE *old = fopen(path,"a"); assert(old);
    fputs("previous launch\n",old); fclose(old);
    struct stat st; assert(!stat(path,&st));
    assert((st.st_mode & 07777) == 0644); /* Original bootstrap is rejected. */
    ino_t inode = st.st_ino;
    int fd = VM27OpenOwnedApplicationLogV1(path,geteuid(),getegid());
    assert(fd >= 3 && !fstat(fd,&st));
    assert(st.st_ino == inode && (st.st_mode & 07777) == 0600);
    assert(fcntl(fd,F_GETFL) & O_APPEND);
    assert(write(fd,"new launch\n",11) == 11); close(fd);
    char contents[64] = {0}; old = fopen(path,"r"); assert(old);
    assert(fread(contents,1,sizeof(contents),old) == 27); fclose(old);
    assert(!strcmp(contents,"previous launch\nnew launch\n"));
    assert(!link(path,alias));
    assert(VM27OpenOwnedApplicationLogV1(path,geteuid(),getegid()) < 0);
    assert(!unlink(alias)); assert(!symlink(path,alias));
    assert(VM27OpenOwnedApplicationLogV1(alias,geteuid(),getegid()) < 0);
    assert(!unlink(alias));
    assert(VM27OpenOwnedApplicationLogV1(path,geteuid()+1,getegid()) < 0);
    assert(!unlink(path));
    fd = VM27OpenOwnedApplicationLogV1(path,geteuid(),getegid());
    assert(fd >= 3 && !fstat(fd,&st) && (st.st_mode & 07777) == 0600);
    close(fd); assert(!unlink(path)); assert(!mkfifo(path,0600));
    assert(VM27OpenOwnedApplicationLogV1(path,geteuid(),getegid()) < 0);
    assert(!unlink(path)); assert(!rmdir(directory));
    puts("PASS: fresh log, 0644 repair, append preservation, symlink/hardlink/owner/FIFO rejection");
    return 0;
}
