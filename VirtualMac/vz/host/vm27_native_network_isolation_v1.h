#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
enum {VM27_NAT_FRAME_DENY=0,VM27_NAT_FRAME_ALLOW=1,VM27_NAT_FRAME_NEEDS_HOST_ADDRESSES=2};
static inline uint16_t VM27NatBE16(const uint8_t *p){return (uint16_t)p[0]<<8|p[1];}
static inline uint32_t VM27NatBE32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
// This NAT has no IPv6 configuration or L2 bridge. Each VM owns its slirp
// instance and packet socket. Host services are not exposed via the gateway,
// other local host addresses, or another address in the private VM subnet.
static inline int VM27NatFramePolicyV1(const uint8_t *p,size_t n,uint32_t subnet,
                                      bool ownedRadioEndpoints,
                                      const uint32_t *hostAddresses,size_t hostCount,
                                      bool hostSnapshotValid){
 if(!p||n<14)return VM27_NAT_FRAME_DENY;
 uint16_t type=VM27NatBE16(p+12);
 if(type==0x0806)return n>=42&&VM27NatBE16(p+14)==1&&VM27NatBE16(p+16)==0x0800&&p[18]==6&&p[19]==4?VM27_NAT_FRAME_ALLOW:VM27_NAT_FRAME_DENY;
 if(type!=0x0800||n<34)return VM27_NAT_FRAME_DENY;
 const uint8_t *ip=p+14;size_t ihl=(ip[0]&15)*4,total=VM27NatBE16(ip+2);
 if(ip[0]>>4!=4||ihl<20||ihl>total||total>n-14)return VM27_NAT_FRAME_DENY;
 uint32_t destination=VM27NatBE32(ip+16);uint16_t fragmentation=VM27NatBE16(ip+6);uint8_t protocol=ip[9];
 bool whole=(fragmentation&0x3fff)==0;
 unsigned sourcePort=0,destinationPort=0;
 if(whole&&(protocol==6||protocol==17)&&total-ihl>=8){sourcePort=VM27NatBE16(ip+ihl);destinationPort=VM27NatBE16(ip+ihl+2);}
 // DHCP/DNS and an ICMP echo of the virtual gateway are local slirp services;
 // they work without a physical association or a successful host enumeration.
 if(whole&&protocol==17&&sourcePort==68&&destinationPort==67&&
    (destination==0xffffffff||destination==(subnet|2)))return VM27_NAT_FRAME_ALLOW;
 if(destination==(subnet|3)&&whole&&(protocol==6||protocol==17)&&destinationPort==53)return VM27_NAT_FRAME_ALLOW;
 if(destination==(subnet|2)&&whole&&protocol==1&&total-ihl>=8&&ip[ihl]==8)return VM27_NAT_FRAME_ALLOW;
 // Existing owned radio transports are explicit Unix mappings, not general
 // host listeners. Preserve only these two ports when enabled for this VM.
 if(ownedRadioEndpoints&&destination==(subnet|4)&&whole&&protocol==6&&
    (destinationPort==39028||destinationPort==39029))return VM27_NAT_FRAME_ALLOW;
 uint32_t destinationSubnet=destination&0xffffff00;
 if(destinationSubnet==subnet||destinationSubnet==UINT32_C(0x0a000200)||
    destinationSubnet==UINT32_C(0x0a000300)||(destination>>24)==127||
    (destination>>24)==0||destination>=0xe0000000)return VM27_NAT_FRAME_DENY;
 if(!hostSnapshotValid)return VM27_NAT_FRAME_NEEDS_HOST_ADDRESSES;
 if(hostCount&&!hostAddresses)return VM27_NAT_FRAME_DENY;
 for(size_t i=0;i<hostCount;i++)if(destination==hostAddresses[i])return VM27_NAT_FRAME_DENY;
 return VM27_NAT_FRAME_ALLOW;
}
