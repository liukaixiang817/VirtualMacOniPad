/* Real signed App/child bytes and filesystem reads; no VMM execution. */
#include "modern_xpc_large_private_consumer_v3.c"
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 9) return 2;
    VM27LargeServiceInfo child = {0};
    if (strlen(argv[1]) >= sizeof(child.executablePath)) return 3;
    strcpy(child.executablePath, argv[1]); strcpy(child.executableSHA256, argv[2]);
    strcpy(child.executableUUID, argv[4]); child.flags = 2;
    struct stat st; if (stat(argv[1], &st)) return 4; child.executableBytes = st.st_size;
    int status = Authenticate(&child, argv[2], argv[3]);
    VM27BundleParentConfigurationV1 parent = {argv[5], argv[6], argv[7], argv[8], geteuid()};
    VM27BundleParentInspectionV1 inspected = {0};
    int parentStatus = VM27BundleParentInspectV1(&parent, &inspected);
    printf("{\"actualConsumerAuthenticateStatus\":%d,\"actualParentInspectStatus\":%d,"
           "\"parentCodePagesVerified\":%s,\"parentExternalInfoVerified\":%s,"
           "\"parentExternalResourcesVerified\":%s,\"wholeResourceWalkClaimed\":%s}\n",
        status, parentStatus, inspected.codePagesVerified ? "true" : "false",
        inspected.externalInfoSlotVerified ? "true" : "false",
        inspected.externalResourcesSlotVerified ? "true" : "false",
        inspected.wholeBundleResourcesValidated ? "true" : "false");
    return status;
}
