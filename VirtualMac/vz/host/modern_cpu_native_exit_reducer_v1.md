该模块补齐一个确定缺失的值转换边界：旧宿主原生退出值到现代 SDK 的标准 32 字节异常结构。它不执行 CPU、不调用旧 Hypervisor、不创建 Apple USER/VIEW，也不执行重试。独立 macOS27 来宾执行仍未证明。

原13和原27的陷入入口均为 `x16=-5; svc #0x80; ret`。两者 native9 参数均是 `x0=9, x1=NULL`，返回值与 context 的 raw reason 是两个不同字段。原13跳表把 raw2/raw11直接送回 native9；原27的 raw 分派返回内部布尔值1，再交给 native loop/VIEW wrapper。这些值不属于公共退出枚举，不能解释为 errno，也不证明访客执行过指令。

| 来源 | raw reason | syndrome | VA | IPA |
| --- | --- | --- | --- | --- |
| 原13 context version `0x206879700000000e` | `4008:4` | `400c:4` | `4018:8` | `4020:8` |
| 原27 context version `0x2068797003000004` | `4008:4` | `4010:8` | `4020:8` | `4028:8` |

原13的 `LDR w8` 然后 `STR x8` 将 syndrome 零扩展为64位。两者公共结构均为32字节：reason在0，syndrome在8，VA在16，IPA在24。公共退出对象位于原13 USER的`+f0`、原27 USER的`+148`；这不允许互相转换 USER/context 指针。

`VZCPUReduceNativeExitV1` 仅接受已分离的旧宿主数值。`nativeReturnBits != 0`、不同版本、缺失已知字段、未知字段标记、非零reserved以及缓冲区重叠均保持输出原字节并返回明确失败。raw2/raw11只产生`INTERNAL_RETRY`标签，`hasPublicException=0`，没有运行循环。raw1/raw6/raw8只有在全部四个字段已知且 ESR exception class 不为`16/18/3f`时才产生独立拥有的异常数值；那三个原处理分支可能模拟、修改CPU或者重入，必须由完整 provider 另行实现。其余所有raw reason暂不支持，包括虽有已知CANCELED语义但没有实现其完整返回行为的raw0。

未来真实调用者必须在同一 live CPU、原生owner线程、generation、run token的真实post-return读取租约中取得这些字段，然后调用归约器。此函数不验证或制造该租约，也不把输入版本号当作所有权证明。原13公开run的pending控制在入口OR进native670、在返回时清空USER E8并清掉native670的bit6/7；原27还执行真实VIEW转换。这个模块均未实现，不能替换整个`hv_vcpu_run`或把结果地址发布成原生Apple退出对象。它不改变现有`runAllowed=false`以及完整后端未完成的状态。

逐机器字证据、12项旧跳表损坏拒绝、真实v32保存记录以及模型记录位于`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-public-exit-source-audit-v6`。v32实际16轮依次为raw0和15个raw11，PC/X0没有推进；不存在丢失一个已完成异常导致这些数值不推进的证据。本次模型仅执行自有代码，不调用任何native trap或设备API。普通/ASan/UBSan模型验证所有64个EC、缺字段、非零原返回值、未知原因、不同版本、输出保持及重叠拒绝；另有真实C++调用者到C实现的链接检查和严格iOS arm64e object编译。它们验证值转换边界，不验证来宾指令或运行中的原27消费者。

复现命令：`python3 -B VirtualMac/scripts/development/audit-modern-cpu-public-exit-v1.py --output DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-public-exit-source-audit-new`，输出目录必须尚不存在。
