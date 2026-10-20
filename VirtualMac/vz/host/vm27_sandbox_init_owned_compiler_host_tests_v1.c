#define VM27_SANDBOX_OWNED_ADAPTER_TESTING 1
#include "vm27_sandbox_init_owned_compiler_v1.c"
/* All compiler/native functions below are HOST mocks. No sandbox is applied. */
typedef struct { const char *builtin;unsigned char *data;uint64_t size; } MockProfile;
static unsigned assertions,creates,sets,compiles,applies,paramFrees,profileFrees,resourceCalls,originalCalls;
static unsigned char fixture[COMPILED_BYTES];
static bool roleOK,resourceOK,resolveOK,changeResources,failCreate,failSet,failCompile,badName,badSize,badData,corrupt;
static int callbackErrno,applyResult,originalResult;static void *produced;
static bool originalOK;
static void Require(bool value,const char *label) {
    ++assertions;if (!value) { fprintf(stderr,"FAIL %s\n",label);exit(1); }
}
static void Reset(void) {
    creates=sets=compiles=applies=paramFrees=profileFrees=resourceCalls=originalCalls=0;
    roleOK=resourceOK=resolveOK=originalOK=true;
    changeResources=failCreate=failSet=failCompile=badName=badSize=badData=corrupt=false;
    callbackErrno=0;applyResult=0;originalResult=77;produced=NULL;
    atomic_flag_clear_explicit(&ownedAttempt,memory_order_release);
}
static void *MockCreate(void) { ++creates;errno=callbackErrno;return failCreate?NULL:malloc(1); }
static int MockSet(void *params,const char *key,const char *value) {
    ++sets;Require(params && !strcmp(key,"IMPORT_DIR") && !strcmp(value,IMPORTS),"exact own IMPORT_DIR only");
    errno=callbackErrno;return failSet?7:0;
}
static void *MockCompile(const char *path,void *params,char **error) {
    ++compiles;Require(!strcmp(path,ORIGINAL_PROFILE) && params && error,"original caller path retained");
    errno=callbackErrno;
    if (failCompile) { *error=strdup("actual mock compiler error");return NULL; }
    MockProfile *p=calloc(1,sizeof(*p));Require(p!=NULL,"allocate actual mock producer object");
    p->data=malloc(COMPILED_BYTES);Require(p->data!=NULL,"allocate mock producer data");
    memcpy(p->data,fixture,COMPILED_BYTES);p->size=COMPILED_BYTES;
    if (badName) p->builtin="unsupported named result";
    if (badSize) --p->size;
    if (corrupt) p->data[0]^=1;
    if (badData) { free(p->data);p->data=NULL; }
    produced=p;return p;
}
static int MockApply(const void *actual) {
    ++applies;Require(actual==produced,"same exact producer opaque pointer passed");
    errno=callbackErrno;return applyResult;
}
static void MockFreeProfile(void *actual) {
    ++profileFrees;Require(actual==produced,"same producer frees actual returned object");
    MockProfile *p=actual;free(p->data);free(p);produced=NULL;errno=EBADF;
}
static void MockFreeParams(void *params) { ++paramFrees;Require(params!=NULL,"free actual params once");free(params);errno=EBUSY; }
static bool Resolve(Operations *ops) {
    *ops=(Operations){MockCreate,MockSet,MockCompile,MockFreeParams,MockFreeProfile,MockApply};return resolveOK;
}
static bool Role(void) { return roleOK; }
static bool Resources(void) { ++resourceCalls;return resourceOK && !(changeResources && resourceCalls==2); }
static int MockOriginal(const char *profile,uint64_t flags,const char *const parameters[],char **out) {
    ++originalCalls;Require(profile && flags==2 && parameters!=NULL,"non3 original arguments unaltered");
    *out=strdup("actual native passthrough result");errno=ENOENT;return originalResult;
}
static NativeInit OriginalInit(void) { return originalOK?MockOriginal:NULL; }
static int Call(char **error) { return VM27SandboxInitWithOwnedCompilerV1(ORIGINAL_PROFILE,3,NULL,error); }
static void NoApply(void) { Require(applies==0,"failed admission/setup never applies"); }

int main(int argc,char **argv) {
    Require(argc==2,"fixed actual fixture input");FILE *file=fopen(argv[1],"rb");Require(file!=NULL,"open genuine compiled fixture");
    Require(fread(fixture,1,sizeof(fixture),file)==sizeof(fixture) && fgetc(file)==EOF,"exact genuine fixture length");
    Require(fclose(file)==0 && SHA(fixture,sizeof(fixture),COMPILED_SHA),"genuine fixture whole SHA");
    char *error=NULL;Reset();
    Require(Call(&error)==0 && error==NULL,"mock success preserves native result");
    Require(creates==1 && sets==1 && compiles==1 && applies==1 && paramFrees==1 && profileFrees==1 && errno==0,"once exact opaque lifecycle and native errno survives free");
    Require(Call(&error)==-1 && errno==EALREADY && applies==1,"second call rejected without another apply");free(error);error=NULL;
    Reset();roleOK=false;Require(Call(&error)==-1 && errno==EACCES && creates==0,"wrong role rejected");NoApply();free(error);error=NULL;
    Reset();resourceOK=false;Require(Call(&error)==-1 && creates==0,"wrong resource rejected");NoApply();free(error);error=NULL;
    Reset();resolveOK=false;Require(Call(&error)==-1 && errno==ENOTSUP && creates==0,"wrong provider rejected");NoApply();free(error);error=NULL;
    Reset();failCreate=true;callbackErrno=ENOMEM;Require(Call(&error)==-1 && errno==ENOMEM && paramFrees==0,"real NULL params owns nothing");NoApply();free(error);error=NULL;
    Reset();failSet=true;callbackErrno=E2BIG;Require(Call(&error)==-1 && errno==E2BIG && paramFrees==1 && compiles==0,"failed set frees only actual params");NoApply();free(error);error=NULL;
    Reset();failCompile=true;callbackErrno=EINVAL;Require(Call(&error)==-1 && errno==EINVAL && error && !strcmp(error,"actual mock compiler error"),"actual compiler error is retained");
    Require(paramFrees==1 && profileFrees==0,"failed compile releases actual params");NoApply();free(error);error=NULL;
    Reset();failCompile=true;Require(Call(NULL)==-1 && errno==0,"NULL output buffer releases actual local error and preserves raw0errno");NoApply();
    Reset();badName=true;Require(Call(&error)==-1 && profileFrees==1 && paramFrees==1,"named producer rejected with matched cleanup");NoApply();free(error);error=NULL;
    Reset();badSize=true;Require(Call(&error)==-1 && profileFrees==1,"wrong produced size rejected");NoApply();free(error);error=NULL;
    Reset();badData=true;Require(Call(&error)==-1 && profileFrees==1,"NULL produced data rejected");NoApply();free(error);error=NULL;
    Reset();corrupt=true;Require(Call(&error)==-1 && profileFrees==1,"wrong actual produced SHA rejected");NoApply();free(error);error=NULL;
    Reset();changeResources=true;Require(Call(&error)==-1 && profileFrees==1 && resourceCalls==2,"changed resources after compile rejected");NoApply();free(error);error=NULL;
    Reset();applyResult=-1;callbackErrno=EACCES;Require(Call(&error)==-1 && errno==EACCES && applies==1 && profileFrees==1 && paramFrees==1,"real apply error and errno kept through cleanup");free(error);error=NULL;
    Reset();applyResult=-1;Require(Call(&error)==-1 && errno==0 && error && strstr(error,"errno=0"),"native failure errno0 never forged to EIO");free(error);error=NULL;
    Reset();const char *params[]={"other","value",NULL};
    Require(VM27SandboxInitWithOwnedCompilerV1(ORIGINAL_PROFILE,3,params,&error)==-1 && errno==ENOTSUP && creates==0,"new flags3 parameters unsupported");NoApply();free(error);error=NULL;
    Require(VM27SandboxInitWithOwnedCompilerV1("/other.sb",3,NULL,&error)==-1 && errno==ENOTSUP,"other flags3 resource unsupported");NoApply();free(error);error=NULL;
    Reset();Require(VM27SandboxInitWithOwnedCompilerV1("original-native",2,params,&error)==77 && errno==ENOENT && originalCalls==1 && creates==0,"non3 returns actual native result including nonzero");free(error);error=NULL;
    Reset();originalOK=false;Require(VM27SandboxInitWithOwnedCompilerV1("original-native",2,params,&error)==-1 && errno==ENOTSUP && originalCalls==0,"non3 unavailable identity fails clearly");free(error);
    printf("HOST_ADAPTER_RESULT assertions=%u nativeCompilerCalls=0 nativeApplyCalls=0 deviceOperations=0 allCallbacksMock=1\n",assertions);
    return 0;
}
