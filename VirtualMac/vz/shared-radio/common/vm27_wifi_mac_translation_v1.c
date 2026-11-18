#include "vm27_wifi_mac_translation_v1.h"
#include <string.h>
static uint16_t be16(const uint8_t *p){return (uint16_t)p[0]<<8|p[1];}
static void store16(uint8_t *p,uint16_t n){p[0]=n>>8;p[1]=(uint8_t)n;}
static uint32_t sum16(uint32_t sum,const uint8_t *p,size_t n){while(n>1){sum+=be16(p);p+=2;n-=2;}if(n)sum+=(uint16_t)p[0]<<8;return sum;}
static uint16_t checksum(uint32_t sum){while(sum>>16)sum=(sum&65535)+(sum>>16);return (uint16_t)~sum;}
static int replace(uint8_t *p,const uint8_t *from,const uint8_t *to){if(memcmp(p,from,6))return 0;memcpy(p,to,6);return 1;}
int vm27_wifi_mac_translate_v1(uint8_t *p,size_t n,const uint8_t from[6],const uint8_t to[6]){
 if(!p||!from||!to||n<14||n>1518)return -1;
 int changed=replace(p,from,to)|replace(p+6,from,to);uint16_t type=be16(p+12);size_t at=14;
 for(unsigned i=0;(type==0x8100||type==0x88a8)&&i<2;i++){if(n-at<4)return -1;type=be16(p+at+2);at+=4;}
 if(type==0x0806){
  if(n-at<8)return -1;
  if(be16(p+at)==1&&be16(p+at+2)==0x0800&&p[at+4]==6&&p[at+5]==4){if(n-at<28)return -1;changed|=replace(p+at+8,from,to)|replace(p+at+18,from,to);}
 }else if(type==0x0800){
  if(n-at<20||p[at]>>4!=4)return -1;size_t ihl=(p[at]&15)*4,total=be16(p+at+2);if(ihl<20||total<ihl||total>n-at)return -1;
  if(p[at+9]!=17||be16(p+at+6)&0x3fff)return changed;
  if(total-ihl<8)return -1;uint8_t *udp=p+at+ihl;size_t length=be16(udp+4);if(length<8||length>total-ihl)return -1;
  unsigned src=be16(udp),dst=be16(udp+2);if(!((src==67&&dst==68)||(src==68&&dst==67)))return changed;
  if(length<248)return -1;uint8_t *d=udp+8;size_t size=length-8;if(d[1]!=1||d[2]!=6||memcmp(d+236,"\x63\x82\x53\x63",4))return changed;
  int payloadChanged=replace(d+28,from,to);
  for(size_t pos=240;pos<size;){uint8_t option=d[pos++];if(option==255)break;if(!option)continue;if(pos>=size)return -1;uint8_t count=d[pos++];if(count>size-pos)return -1;if(option==61&&count==7&&d[pos]==1)payloadChanged|=replace(d+pos+1,from,to);pos+=count;}
  if(payloadChanged&&be16(udp+6)){udp[6]=udp[7]=0;uint32_t sum=sum16(17+length,p+at+12,8);uint16_t result=checksum(sum16(sum,udp,length));store16(udp+6,result?result:65535);}
  changed|=payloadChanged;
 }else if(type==0x86dd){
  if(n-at<40||p[at]>>4!=6)return -1;size_t payload=be16(p+at+4);if(payload>n-at-40)return -1;
  uint8_t next=p[at+6];size_t offset=at+40,end=offset+payload;
  for(unsigned i=0;i<8&&(next==0||next==43||next==60);i++){if(end-offset<8)return -1;size_t bytes=((size_t)p[offset+1]+1)*8;if(bytes>end-offset)return -1;next=p[offset];offset+=bytes;}
  if(next!=58||end-offset<8)return changed;uint8_t *icmp=p+offset;size_t size=end-offset,options=0;
  switch(icmp[0]){case 133:options=8;break;case 134:options=16;break;case 135:case 136:options=24;break;case 137:options=40;break;default:return changed;}
  if(size<options)return -1;int payloadChanged=0;
  for(size_t pos=options;pos<size;){if(size-pos<2)return -1;size_t length=(size_t)icmp[pos+1]*8;if(!length||length>size-pos)return -1;if((icmp[pos]==1||icmp[pos]==2)&&length==8)payloadChanged|=replace(icmp+pos+2,from,to);pos+=length;}
  if(payloadChanged){icmp[2]=icmp[3]=0;uint32_t sum=sum16(58+(uint32_t)size,p+at+8,32);store16(icmp+2,checksum(sum16(sum,icmp,size)));}changed|=payloadChanged;
 }
 return changed;
}
