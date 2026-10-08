# Task 编译输出的可选持久缓存

缓存代码位于 `vz/host/modern_pvg_shader_persistent.inc`。只有真实原生
library 创建成功、NSError 为 nil 后才发布；损坏、权限或身份不匹配、
可选预算耗尽时继续使用原转换流程。它不证明 GPU 像素或 UI 已正常。

只构建 Task 单库，使用已核验的两项输入：

```sh
bash scripts/development/build-modern-gputask-compat.sh \
  /absolute/path/ModernRuntimeCompat.dylib \
  /absolute/path/MetalCompat.dylib /absolute/path/fresh-output
```

不要为此调用 `build-virtualmac2.sh` 重建 CPU/VMM 或其他框架。
保存源码、两项依赖、SDK/clang/参数、实际平台与最低系统版本、产物 SHA256、
CDHash、签名/dyld 验证及导出列表。新产物应单独审核，不能直接当成已测试版本。

`persistent_cache_identity.h` 当前保留 2026-10-08 实机验证的 `2a4cc…` 收据
pin，供该安装复现。对没有有效目标设备收据的新安装，构建副本中该 pin 必须
默认为 64 个 `0`；原代码会关闭可选持久缓存。不要把本机 Mac 的 inode/stat
数据或另一台设备的收据当成目标设备身份，也不要只凭二进制 SHA 相同复用收据。

新安装的正确顺序是先安装七个核验过的 compiler 文件及 profile，再在运行时
停机后用只读 identity probe 获取完整 SHA256、before/after/currentPath 精确
stat 和 complete 记录。接受 exit0、空 stderr、七项完整且稳定的结果后，使用
对应版本的收据生成器保留完整 st_mode、mtime/ctime/birth 纳秒等身份字段；
仅排除读取可以改变的 atime，不把 Task 源码 SHA 纳入 compiler 身份。
对规范 JSON 的完整字节取 SHA256，生成与之匹配的 header，然后只重建 Task。

可移植构建应在新的源码构建副本里生成 header；没有已核验收据时用零 pin，
有收据时用其完整 SHA256。引号 include 会先选择 `.inc` 所在目录的 header，
不能仅添加另一个 `-I` 路径便假定覆盖了项目中的 pin。保留原项目和冻结证据。
部署时收据为 root:wheel 0444，`converter-cache-v1` 为 root:wheel 0755，
其收据 SHA 命名的 profile 为 mobile:mobile 0700。保留原 Task 备份，Task 最后
原子提交；回滚先恢复 Task，保留缓存和诊断数据。收据不应放入现有
`--compiler-runtime` 目录：packager 只接受七项 code、profile 和 work，且其
通用 code 权限过滤不能代替收据的 0444 权限。

原生 confstr 缓存有独立的 `native_pvg_cache_identity.h` scope。普通 Task
重启、endpoint 或这次缓存代码调整不应生成新 scope；实际 native ABI 输入变化
才另行生成 scope，并保留旧目录内容。每次真实验证必须分别记录缓存 hit、原生
library 结果、GPU completion/像素和 UI 响应，不能相互替代。

完整着色器输入采集默认关闭。需要复现编译问题时，仅在诊断 helper 的环境中
设置 `VZ_PVG_SHADER_INPUT_AUDIT=1`；其他值不会安装采集包装。静态转换缓存、
持久缓存和原生编译回退独立保留。该开关避免每次 library 创建后同步复制、
哈希及写入诊断输入，不代表图标生成、App 首帧或 GPU 性能已验证。
