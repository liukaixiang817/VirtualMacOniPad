# 应用私有磁盘传输

`modern_disk_io_compat.c` 是给现代后端适配层使用的真实 POSIX 队列：一个持续工作的线程执行 `pread`、`pwrite` 和 `fsync`，完成项返回真实传输长度或负 errno。它没有链接或加载 macOS13 的 VMM/Virtualization/Hypervisor，也没有实现 Apple 私有 `io_rings` ABI。

队列容量包含待执行、正在执行及尚未消费的完成项。容量不足返回 `EAGAIN`，不会覆盖完成项。提交者保留缓冲区，直到消费相应完成项；完成项保存原始 cookie。暂停等待当前请求结束，取消逐项产生 `ECANCELED` 完成项；关闭先等待执行中的请求，再取消未执行请求、连接线程并关闭自己的重复 fd。完成项读完后才能销毁队列。线程连接失败会保留 fd 与句柄，唤醒其他关闭等待者并返回真实错误。超时依据单调时钟，Darwin 条件变量使用相对等待。

最终测试候选为 `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/modern-disk-io-v1/build-v5`。同一源代码的 Mac 原生和 AddressSanitizer 测试各通过 4295 项检查。iPad 原生结果在 `modern-disk-io-native-v4/result.json`：直接子进程 PID30347、UID/EUID501、退出0、4295检查0失败、28ms、禁用虚拟化框架镜像计数0。自有128KiB测试文件已删除，工作线程已连接，子进程已消失，前后文件哈希相同。检查包含真实独立 fd 回读、flush、EOF、只读 fd 错误、背压、暂停取消、关闭取消及四个并发提交线程。

设备仅增加 `/var/mobile/VirtualMacDebug/disk-io-v5` 中的两个诊断代码文件及其准确 trustcache 哈希。三权限候选在普通用户和 Root 下均被私有库 mmap 限制拒绝。最终探针增加 `com.apple.private.amfi.can-execute-cdhash` 后成功；其其他权限仅为 platform-application、no-container、no-sandbox。动态库没有 entitlements，没有修改 iPadOS、系统库、生产 App 或来宾磁盘。

这是可执行、已原生验证的私有传输组件，尚未接入原 macOS27 VMM 的块设备。原 DiskImages2 的88B SQE、订阅回调、40B setup 返回值、生命周期与 PAC 仍须逐项桥接；不得将本组件直接重命名成 `_io_rings_*` 或据此宣布完整 macOS27 后端可以启动。

构建、本地验证及显式设备执行工具分别为 `scripts/development/build-modern-disk-io.py`、`scripts/tests/test-modern-disk-io.c` 和 `scripts/development/run-modern-disk-io-probe.py`。Runner 要求固定 manifest、签名和代码哈希、实际本地测试结果、设备型号及来宾关机检查；默认只验证候选，只有显式 `--run` 才接触设备。密码由执行环境提供，不写入文件。
