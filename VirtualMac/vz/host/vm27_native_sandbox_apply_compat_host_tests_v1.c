/* HOST-only validation. The production main/native apply are never called. */
#define main VM27UncalledProductionMainForHostTest
#include "vm27_native_sandbox_apply_compat_probe_v1.c"
#undef main

static unsigned checks;
static void Require(bool passed,const char *label) {
    ++checks;
    if (!passed) { fprintf(stderr,"FAIL %s\n",label); exit(1); }
}
static void PutFile(int dir,const char *name,const char *bytes,size_t size) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    Require(fd>=0,"create own test file");
    Require(write(fd,bytes,size)==(ssize_t)size,"write only HOST fixture");
    Require(close(fd)==0,"close HOST fixture");
}
int main(void) {
    Require(getuid()==501,"test file ownership profile");
    Require(Digest("abc",3,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),"known SHA256");
    Require(!Digest("abc",3,BLOB_SHA),"wrong SHA rejected");
    Require(!Digest("abc",3,"00"),"short hash rejected");
    Observation baseline={0};
    Require(Baseline(&baseline),"baseline actual successful result shape");
    baseline.check[3]=-1; Require(!Baseline(&baseline),"query error is not baseline allow");
    baseline.check[3]=0; baseline.writeOpen=-1; Require(!Baseline(&baseline),"POSIX inaccessible is not sandbox baseline");
    Observation after={0};
    after.check[2]=after.check[3]=1;
    after.readOpen=after.writeOpen=-1; after.readErrno=EPERM; after.writeErrno=EACCES;
    Require(LocalOracle(&after),"allow and deny queries plus real denied opens");
    after.check[2]=-1; Require(!LocalOracle(&after),"query error is not denied"); after.check[2]=1;
    after.readErrno=ENOENT; Require(!LocalOracle(&after),"missing file is not denied"); after.readErrno=EPERM;
    after.readOpen=0; Require(!LocalOracle(&after),"accepted deny file makes oracle false"); after.readOpen=-1;
    after.nullRead=-1; Require(!LocalOracle(&after),"positive read failure rejected"); after.nullRead=0;
    after.metadata=-1; Require(!LocalOracle(&after),"positive metadata failure rejected");
    char path[]="/private/tmp/vm27-sandbox-compat-host-XXXXXX";
    Require(mkdtemp(path)!=NULL,"exclusive HOST directory");
    int dir=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); Require(dir>=0,"open HOST directory");
    PutFile(dir,"actual","abc",3);
    unsigned char out[4]={0};
    const char *sha="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    Require(ReadPinnedAt(dir,"actual",3,sha,out) && !memcmp(out,"abc",3),"stable FD and exact SHA");
    Require(!ReadPinnedAt(dir,"actual",4,sha,out),"size mismatch rejects before read");
    Require(!ReadPinnedAt(dir,"actual",3,BLOB_SHA,out),"whole-file hash mismatch");
    Require(!ReadPinnedAt(dir,"../actual",3,sha,out),"traversal rejected");
    Require(!ReadPinnedAt(dir,"actual",0,sha,out),"zero-size rejected");
    Require(fchmodat(dir,"actual",0644,0)==0,"change HOST fixture mode");
    Require(!ReadPinnedAt(dir,"actual",3,sha,out),"wrong metadata rejected");
    Require(fchmodat(dir,"actual",0600,0)==0,"restore HOST fixture mode");
    Require(linkat(dir,"actual",dir,"alias",0)==0,"create HOST hardlink counterexample");
    Require(!ReadPinnedAt(dir,"actual",3,sha,out),"multiple links rejected");
    Require(unlinkat(dir,"alias",0)==0,"remove HOST hardlink");
    Require(symlinkat("actual",dir,"symlink")==0,"create HOST symlink counterexample");
    Require(!ReadPinnedAt(dir,"symlink",3,sha,out),"NOFOLLOW symlink rejected");
    Require(unlinkat(dir,"symlink",0)==0 && unlinkat(dir,"actual",0)==0,"remove exact HOST fixture files");
    Require(close(dir)==0 && rmdir(path)==0,"remove exact HOST directory");
    printf("HOST_TEST_RESULT checks=%u nativeApplyCalls=0 nativeSandboxCheckCalls=0 deviceOperations=0\n",checks);
    return 0;
}
