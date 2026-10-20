#include "modern_cpu_optional_abi_v1.h"
_Static_assert(sizeof(hv_vcpu_sme_state_t)==2,"Actual two-bool SDK SME state");
_Static_assert(sizeof(hv_sme_z_reg_t)==4 && sizeof(hv_sme_p_reg_t)==4,"Actual SME selectors");
_Static_assert(sizeof(hv_sme_zt0_uchar64_t)==64,"Actual SDK ZT0 vector bytes");
static hv_return_t BadV1(void){return (hv_return_t)UINT32_C(0xfae94003);}
static hv_return_t UnsupportedV1(void){return (hv_return_t)UINT32_C(0xfae9400f);}
static hv_return_t RefusePointerV1(hv_vcpu_t cpu,const void *p) {
 return p?VM27CPUFactoryRefuseOptionalFeatureV1(cpu):BadV1();
}
hv_return_t _hv_capability(uint32_t selector,uint64_t *out) {
 if(!out)return BadV1();
 switch(selector) {
  case 2:case 3:case 4:case 7:case 9:case 12:case 14:case 15:
  case 16:case 17:case 18:case 19:case 22:case 23:return UnsupportedV1();
  default:return BadV1();
 }
}
hv_return_t hv_sme_config_get_max_svl_bytes(size_t *out){return out?UnsupportedV1():BadV1();}
hv_return_t hv_vcpu_get_sme_state(hv_vcpu_t c,hv_vcpu_sme_state_t *p){return RefusePointerV1(c,p);}
hv_return_t hv_vcpu_set_sme_state(hv_vcpu_t c,const hv_vcpu_sme_state_t *p){return RefusePointerV1(c,p);}
hv_return_t hv_vcpu_get_sme_z_reg(hv_vcpu_t c,hv_sme_z_reg_t r,uint8_t *p,size_t n) {
 return (uint32_t)r<32 && n?RefusePointerV1(c,p):BadV1();
}
hv_return_t hv_vcpu_set_sme_z_reg(hv_vcpu_t c,hv_sme_z_reg_t r,const uint8_t *p,size_t n) {
 return (uint32_t)r<32 && n?RefusePointerV1(c,p):BadV1();
}
hv_return_t hv_vcpu_get_sme_p_reg(hv_vcpu_t c,hv_sme_p_reg_t r,uint8_t *p,size_t n) {
 return (uint32_t)r<16 && n?RefusePointerV1(c,p):BadV1();
}
hv_return_t hv_vcpu_set_sme_p_reg(hv_vcpu_t c,hv_sme_p_reg_t r,const uint8_t *p,size_t n) {
 return (uint32_t)r<16 && n?RefusePointerV1(c,p):BadV1();
}
hv_return_t hv_vcpu_get_sme_za_reg(hv_vcpu_t c,uint8_t *p,size_t n){return n?RefusePointerV1(c,p):BadV1();}
hv_return_t hv_vcpu_set_sme_za_reg(hv_vcpu_t c,const uint8_t *p,size_t n){return n?RefusePointerV1(c,p):BadV1();}
hv_return_t hv_vcpu_get_sme_zt0_reg(hv_vcpu_t c,hv_sme_zt0_uchar64_t *p){return RefusePointerV1(c,p);}
hv_return_t hv_vcpu_set_sme_zt0_reg(hv_vcpu_t c,const hv_sme_zt0_uchar64_t *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_amx_prepare(hv_vcpu_t c){return VM27CPUFactoryRefuseOptionalFeatureV1(c);}
hv_return_t _hv_vcpu_amx_query_active_context(hv_vcpu_t c,bool *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_get_amx_state_t_el1(hv_vcpu_t c,uint64_t *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_set_amx_state_t_el1(hv_vcpu_t c,uint64_t v){(void)v;return VM27CPUFactoryRefuseOptionalFeatureV1(c);}
hv_return_t _hv_vcpu_get_amx_x_space(hv_vcpu_t c,void *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_set_amx_x_space(hv_vcpu_t c,const void *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_get_amx_y_space(hv_vcpu_t c,void *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_set_amx_y_space(hv_vcpu_t c,const void *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_get_amx_z_space(hv_vcpu_t c,void *p){return RefusePointerV1(c,p);}
hv_return_t _hv_vcpu_set_amx_z_space(hv_vcpu_t c,const void *p){return RefusePointerV1(c,p);}
void *_hv_vcpu_get_context(hv_vcpu_t c) {
 hv_return_t status=VM27CPUFactoryRefuseOptionalFeatureV1(c);
 if(status==BadV1())return NULL; /* No actual published CPU for this ID. */
 /* This pointer ABI has no error channel. A valid CPU must never get a false view. */
 __builtin_trap();
}
