#include "vm27_guest_vsock_ssh_helper_v1.h"
#include <errno.h>
#include <string.h>
static const uint8_t magic_v1[8] = {'V','M','2','7','S','S','H','1'};
void vm27_ssh_vsock_header_v1(uint8_t out[32],uint16_t type,
                            uint32_t error,const uint8_t token[16]) {
    memset(out,0,32); memcpy(out,magic_v1,8); out[9]=1;
    out[10]=(uint8_t)(type>>8);out[11]=(uint8_t)type;
    for(unsigned i=0;i<4;i++)out[12+i]=(uint8_t)(error>>(24-8*i));
    if(token)memcpy(out+16,token,16);
}
int vm27_ssh_vsock_parse_v1(const uint8_t in[32],uint16_t *type,
                          uint32_t *error,uint8_t token[16]) {
    if(!in||!type||!error||!token)return EINVAL;
    if(memcmp(in,magic_v1,8)||in[8]!=0||in[9]!=1)return EPROTO;
    uint16_t t=((uint16_t)in[10]<<8)|in[11];
    uint32_t e=0;for(unsigned i=0;i<4;i++)e=(e<<8)|in[12+i];
    uint8_t nz=0;for(unsigned i=0;i<16;i++)nz|=in[16+i];
    if(t<1||t>4||(t==4?e==0:e!=0)||(t==1?nz!=0:nz==0))return EPROTO;
    *type=t;*error=e;memcpy(token,in+16,16);return 0;
}
