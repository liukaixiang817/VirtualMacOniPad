# 框架后端选择

在设置的“兼容性”区域，“框架后端”选择 CPU、VMM 和 Virtualization
框架版本。已有安装没有保存选择时使用 `13.2.1`，保留可运行的组合。
选择保存在 `Settings.plist` 的 `FrameworkBackendVersion`；保存失败会恢复
原值并显示错误。

2.0前端还提供只读定位入口 `virtualmac2://framework-backend`：打开设置并
在首次 `viewDidAppear:` 时滚动到框架后端行，展示选择、已加载版本及
解释文本。它不会更改选择、启动来宾或弹出版本选择菜单。关闭设置后
重新打开会重新定位；在同一设置页面再次出现时不会反复抢走滚动位置。
URL仅接受当前App注册的scheme；未知action在切换到虚拟机库前拒绝。

| 选择 | 当前行为 |
| --- | --- |
| macOS 13.2.1 | 使用已验证的 CPU、VMM 和 Virtualization 框架运行来宾。 |
| macOS 27（开发中） | 可以保存选择，但 CPU/VMM/VZ 移植尚未就绪；启动和安装会明确拒绝。不会自动运行13.2.1代替它。 |

未就绪的27后端使用普通“框架后端”提示，不会作为崩溃报告处理，也不会自动开启下次启动的调试日志。

GPU后端独立配置。2.0测试版现有运行组合仍使用macOS27的PVG、GPU Task、
MetalSerializer及私有编译组件。选择CPU框架版本不会把GPU版本一并切换；
GPU27通过也不能证明整个CPU/VMM/VZ已使用27。

来宾启动或运行、macOS安装期间不能切换后端，也不能重置设置。
启动和安装互斥。一次运行开始时固定所选版本及其运行库目录，结束后
解除运行锁。框架已经尝试加载后，进程不能再混装另一个版本；不同版本
需要关闭来宾、退出并重新打开App。重开App本身不会使开发中的27变得可用。

“已加载的框架后端”显示本进程成功加载、完成VZ兼容检查的版本；尚未
加载时显示“未加载”。它与保存的选择分开：关闭13来宾后选择27，已加载
行仍显示13。该行不是完整来宾启动、CPU执行或磁盘I/O测试通过的证明。

13路径来自App的 `VirtualMacRuntimeRoot`，2.0测试版为
`/var/root/VirtualMac2`。27候选使用独立的 `VirtualMac27RuntimeRoot`，或
默认的 `backends/macos27` 子目录；目录存在也不会绕过未就绪检查。
当前安装器仍使用旧版安装组件，27安装尚未开放。

现有VZ绑定代码只接受已核验的22D68映像UUID
`DCFC0A79-7728-3089-94D7-1508E71F38E5`及其准确的
`__AUTH_CONST`布局。在修改页面保护或认证GOT槽前先检查真实dyld映像；
未知版本，包括27，会拒绝旧绑定偏移。27需要自己的绑定及私有帧/RPC
契约，不能仅改版本文字或文件名。旧RPC布局诊断也只在已加载13时执行。

前端测试部署应先确认来宾、VMM及GPU任务已正常停止，备份整个
`VirtualMac2.app`到应用目录之外的Root私有目录，并记录原文件哈希及
权限。仅替换已签名核验的前端候选，保留旧运行库、来宾磁盘、身份文件
和GuestTools；失败时恢复整包备份。安装后验证13启动、27拒绝且无回退、
关闭后切回13以及实际VZ身份。前端选择功能的部署不代表完整27后端通过，
也不修改已经发布的Release。

实现入口：`vz/host/VZBackendSelection.m`、`VZAppSettings.m`、
`VZSettingsViewController.m`、`VirtualMacApp.m`和`vzxpchook.m`；
身份检查位于 `VZFrameworkIdentity.h`，本地生命周期测试位于
`scripts/tests/test-backend-selection.m`。

v6定位入口的三个UI实现文件为 `vz/host/VirtualMacApp.m`（注册scheme及
action白名单）、`VZVMLibraryViewController.m`（创建聚焦框架行的设置
页面）、`VZSettingsViewController.m`（首次显示后滚动；普通设置入口保持
原行为）。相应新方法声明位于后两个控制器的头文件。
