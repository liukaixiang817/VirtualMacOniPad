"""Small native CPU compatibility additions to the pinned owner implementation."""
from pathlib import Path


def apply_native_features(root: Path, text: str) -> str:
    marker = 'static VZKernelStatus GICHandlePostV20(VZKernelCPUGICOwnerV18 *o,PendingRunAccessV14 *a,'
    assert text.count(marker) == 1
    helper = (root / 'VirtualMac/vz/host/vm27_id_aa64isar3_v1.inc').read_text()
    text = text.replace(marker, helper + '\n' + marker)
    marker = ' } else if(ec==0x18)s=VM27GICHandleSystemV1(o->engine,&o->identity,esr,source,&trap);'
    assert text.count(marker) == 1
    replacement = ''' } else if(VM27IDAA64ISAR3MRSV1(esr)) {
  uint32_t featurePSTATE = 0;
  if(!GICPostPSTATEV20(a,&featurePSTATE))s=VZ_KERNEL_CONTEXT_UNREADABLE;
  else if(!VM27IDAA64ISAR3PrepareV1(esr,featurePSTATE,&trap))s=VZ_KERNEL_UNSUPPORTED;
  else s=VZ_KERNEL_OK;
 } else if(ec==0x18)s=VM27GICHandleSystemV1(o->engine,&o->identity,esr,source,&trap);'''
    return text.replace(marker, replacement)
