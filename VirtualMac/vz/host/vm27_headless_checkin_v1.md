原 macOS 27 VMM 在 RVA 0xbfac 唯一调用 _LSApplicationCheckIn：w0=-2，x1 为 CFBundleGetMainBundle → CFBundleGetInfoDictionary 的借用字典；原 x0 返回值立即被下一条 ADRP/LDR 覆盖。强导入 index 90/ordinal 5、stub 0x411b44、认证 GOT 0x4c6230 均保留。

genuine LaunchServices 代码返回 nullable 64-bit CF 对象，非旧 shim 的 int/noErr。其具体返回 typedef 与外部所有权尚未完全证明，故此头文件使用 opaque CFTypeRef。这里明确提供应用内、headless 的登记状态；不会进行 iPadOS LaunchServices daemon/global 登记，不会声称返回系统 ASN。

有效会话 -2 与有限 property-list CFDictionary 的首次调用创建不可变真实 CF record（PID/euid、随机 CFUUID、不可变 BundleInfo 深复制）；等价信息重试返回同一借用 identity，非等价信息失败并保留原状态。调用者须传有效 live CF 对象组成的字典树，调用期间不得同时修改输入；不把任意地址作为可读 CF。节点 512、深度 8、数组/字典单项数量 256、累计数据 64 KiB、字符串 4096 UTF-16 code units。过程锁保护同进程所有权；fork 子进程不可继承使用父登记 identity。借用 record 由 provider 持有至进程退出，独立 copy API 返回真实 retain 的记录供调用者释放。

此接口仅候选，不自动接入、签名或部署原 VMM。它不创建 VM/vCPU，不提交 GPU，不执行来宾指令，完整 macOS 27 后端仍未完成。
