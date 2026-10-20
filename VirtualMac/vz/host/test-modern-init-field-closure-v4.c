#include "modern_cpu_kernel_initialization_v3_private.h"
#include <stdio.h>
#include <stdlib.h>
bool ReferenceWritable(uint32_t,size_t);
int main(void){unsigned checks=0;for(uint32_t offset=0;offset<0x8000;++offset)for(size_t bytes=0;bytes<=32;++bytes){++checks;if(VZKernelInitOffsetWritable(offset,bytes)!=ReferenceWritable(offset,bytes)){fprintf(stderr,"offset0x%x bytes%zu\n",offset,bytes);return 1;}}uint32_t edges[]={0xffffffef,0xfffffff0,0xfffffff8,0xffffffff};for(unsigned i=0;i<4;++i)for(size_t bytes=0;bytes<=32;++bytes){++checks;if(VZKernelInitOffsetWritable(edges[i],bytes)!=ReferenceWritable(edges[i],bytes))return 1;}printf("full shared context and uint32 boundary field closure equivalence checks=%u PASS\n",checks);return 0;}
