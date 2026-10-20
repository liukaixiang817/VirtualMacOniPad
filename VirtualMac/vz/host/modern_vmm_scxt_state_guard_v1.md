# SCXT save/restore guard and CNTP connection contract v1

本源码是可独立编译的应用 VMM 状态片段。它没有导出 `hv_*`，没有安装原 VMM 适配器、修改原 Apple Mach-O、增加 native 操作或授予设备权限。

调用方必须从当前同一 CPU 的实际来宾特征配置提供完整 `ID_AA64PFR0_EL1`、`ID_AA64PFR1_EL1`。不能使用旧设备采样作为默认，不能仅为绕过恢复而改写已提供的特征。PFR0.CSV2 的位置为 `[59:56]`，PFR1.CSV2_frac 为 `[35:32]`。已知 CSV2=2/3 对应有 SCXTNUM；CSV2=0/1 未暴露 FEAT_CSV2_2。仅已知编码接受，未知值不能降为缺失。CSV2_frac 仅 CSV2=1 时接受0/1/2，其余只接受0，是本片段的保守支持范围，不能声称白皮书逐条规定所有组合。

架构依据由 Root 本次核实：[Arm Spectre-BHB White Paper v1.6](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Security%20Update%2008%20March%202022/Spectre-BHB%20White%20Paper%20v1.6.pdf)，PDF第5页（零基4）CSV2 表及第8页（零基7）的新增值3；[Linux arm64 sysreg 源码](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/tools/sysreg)，本次读取行1128–1138、1233–1237。CSV2=0 的推测防护行为未知，不能把它描述成已证明硬件防护不存在。Guest 未暴露 FEAT_CSV2_2 与推测防护结论是不同概念。本子任务没有访问这些远端链接。

`VM27VMMSaveSCXTSectionV1` / `VM27VMMRestoreSCXTSectionV1` 的调用方必须在真实 owner pthread 上持有该 CPU 的 registry borrow/lease 和锁，并保持同一 generation。`binding` 是调用方提供的已验证身份，不是本纯片段重新验证了 native CPU 所有权。此处保证 frame 身份及全部 PFR 值精确匹配；不支持跨 CPU/代际迁移。

缺失时两个 callback 都不执行，frame 的 `validMask=0`，返回 `OMITTED`（独立枚举值1，绝不是 `HV_SUCCESS`）。无效槽内的存储字节不能作为架构状态读出或恢复。存在时只调用两个真实 typed getter/setter。getter 任一失败不发布 frame；setter 顺序执行，失败时保留真正 signed32 返回及 attempted/completed mask，调用方保留 CPU/frame 处理已完成的写入，不能声称原子恢复。现有 public SYS provider 对 SCXT 仍明确 unsupported，本模块不会改变这个返回或替换成软件 shadow success。

原 VMM 必须在 save/restore **四处实际调用**应用相同规则。完整原 save 为 `0x2875a8..0x28a258`：EL0 getter `0x288940` 写 frame `+0x760`，EL1 getter `0x288960` 写 `+0x768`。完整 restore 为 `0x28a508..0x28cc24`：EL0 setter `0x28b58c`、EL1 setter `0x28b5a0`，两者真实失败分支到 `0x28cb8c`。源码接入应在 same-CPU 锁内获取 supplied PFRs；save 缺失时不执行原 setter/store 序列且将 sidecar 标为缺失；restore 先校验 sidecar/profile，一旦缺失就跳过两个原 setter。存在时仍走真实公开 SYS 路径并保留原错误处理。不可仅拦截 public getter/setter 返回成功，因为原调用者会把伪值放入有效 frame。

这个 SCXT 片段是完整的片段，不是原 VMM 整帧完成证明。完整原 save / restore 各含59个 `__hv_vcpu_get_context`。已封存的53个 restore 端口还留下 `0x28b16c/0x28b1ec/0x28bd70/0x28c7cc/0x28c914/0x28caf0`；前两者在每条普通成功恢复路径必经，modern context 字段分别 `+0x6a0/+0x410` 尚无闭合逻辑路由。其余四者对应 `+0xca8/+0xbc0/+0x390/+0xaf8`。还没有对应完整59个 save 端口。新 profile 省略 SCXT 并不省略这两个必经 context 调用，不能据此标记整帧完整。不同版本 native context 的相同数字偏移不是架构同一性的证明。

## CNTP 的真实最小后续接口

目前必须保持 `CNTP_CTL_EL0 (0xdf11)` / `CNTP_CVAL_EL0 (0xdf12)` unsupported。原 VMM 必经 restore 调用分别为 `0x28abb0/0x28abc4`，frame `+0x3a0/+0x3a8`；save 的真实 getter 为 `0x287a54/0x287a74`。原13物理 SYS mapper 没有两条路由，不能借用 `CNTV_CTL(df19)->old+0x430`、`CNTV_CVAL(df1a)->old+0x3e8`。

原27 timer dispatcher `0x5c44..0x5eb0` 先验证 CPU flag `+0x13a`，再进入真正 CPU timer object `+0x2c0`。CTL getter `0x73674..0x736f4` 从 timer state 的真实物理 counter 与 CVAL 比较生成 ISTATUS（bit2），仅 low2 控制位可存。CTL setter `0x73774..0x73830` / CVAL setter `0x7396c..0x73a20` 都对实际 state `+0x10` 加锁并调用 `0xd69c` 更新。该 update 有真实 deadline 调度、取消及 counter owner 虚调用。复制这几个缓存字段不足以实现 timer。

后续源码至少需要在同一 VM/CPU 所有权协议下闭合以下实际接口，缺任一消费者必须失败：

1. `readGuestPhysicalCounter(owner, generation, &ticks)`：给出该 guest 的 CNTP counter 单位和真实时基，不能假设它等于 CNTVCT 或 host 纳秒。
2. `schedulePhysicalDeadline(owner, generation, cval, callbackToken)` / `cancelPhysicalDeadline(...)`：真实 deadline 调度，owner-generation token 防止销毁后 callback，callback 能唤醒阻塞 Run。CTL 的 ENABLE/IMASK 与 CVAL 改变要取消或重新调度，读 CTL 的 ISTATUS 来自真实 counter 比较。
3. `setPhysicalTimerPPILevel(sameVMGIC, sameCPU, asserted)`：真实同 VM 的 GIC PPI 电平消费者；masked/disabled 状态需撤销电平，不能将 timer cache 更新当作已注入中断。不得猜 PPI 编号，需连接 guest 当前 GIC/timer 配置的真实路由。
4. `handleGuestSYSExit(...)`：闭合 EC0x18 SYS trap 的解码、权限、寄存器读写、PC 前进和失败传播，并接入上述 timer state。当前 exit reducer 对 EC0x18 明确 unsupported。
5. 真正 Run 的 pending IRQ 入口/退出和安全 wake：当前 `VZKernelCPURunOwnedStepV7` 拒绝任何 pending IRQ/FIQ。必须实现原13已审查 CONTROL0 协议的真实 `+0x670` RMW/退出清除，不能对未知 native ABI 写入。没有此 Run 消费者就不能声明 timer 中断正常。

`vtimerOffset` 的真已审查 old13 setter 只写 `+0x6a0` 并 `dirty+0x748 |=4`。真实 SDK 规定 `CNTVCT_EL0 = mach_absolute_time() - vtimer_offset`。它属于虚拟 counter 路径，不会自动提供 CNTP counter/deadline/GIC；不得增加未经依据的 `+0x670/+0x678` 写入来“连接”CNTP。

本版本没有 CNTP 缓存实现；没有设备调用、签名、trust cache 或 native VM/CPU 执行。Mac normal/ASan/UBSan fixture 只证明当前纯 guard 的 profile/identity/validity/真实错误传播；实际 boot/display 仍由 Root 的整体任务继续完成。
