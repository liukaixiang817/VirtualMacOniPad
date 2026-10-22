2026-10-21 启动热点进展：Runtime133/CPU76/GIC12/App187/Dev174/Normal198 已真实冷启动交接0。中断回调计数改为原生32位原子值，物理定时批次在完成状态发布后依次释放CPU与控制器存活计数，减少一次全局锁往返；其余28个CPU对象、原生接口和IRQ/调度语义保持。功能/差分/四所有者并发与Reset 53806检查、TSAN 54486检查通过。真机壁纸/菜单/Dock/设置可见主区及侧栏图标完整，图标服务PID615 runs1/never exited；原生暂停state2与恢复state1均verified1/nativeError0，恢复后剪贴板HELLO重连。冷启动首帧41–46秒且包含一次3秒采样，不据此声称稳定加速或30秒Ready。实际采样仍定位物理定时入口、虚拟定时路由和GetLines全局锁争用，应继续减少无状态变化的重复读取。源码与证据说明docs/independent27-gic-atomic-pins.md。当前版本的正常关机清理尚待下一次真实停止时确认，不重复泛化渲染探针；beta2仍暂缓上传。

2026-10-21 GUI 优先更新：Runtime132/CPU75/GIC11/App186/Normal197 保持独立 macOS27 后端。真实冷启动与退出设置→Dock重开后，原生USB画面确认通用主区域与侧栏所有可见图标，以及关于本机、显示器、菜单栏页面、壁纸/菜单/Dock均完整。图标服务PID530 runs1/never exited（03:22:13UTC，登录03:09:45UTC，持续超过12分钟）。两条真实崩溃路径分别为CoreGraphics缓存释放与CoreImage DAG内核释放；仅关闭其中之一均未过冷验证。当前来宾用户同时启用两个原生兼容选项，原生Metal保留。可恢复、构建限定的源码在vz/guest/configure_native_graphics_pipeline_v1.sh，说明在docs/independent27-native-graphics-compatibility.md。旧CI_DISABLE_LOADING_ARCHIVES选项已恢复不存在。该兼容措施暂缓高级DAG生命周期实现，未修改系统框架；尚未自动部署到新来宾。一次冷GUI回归不等于所有App无错误；首帧44–50秒，约30秒完整Ready未达标，开机/登录负载、全应用GUI、性能和物理多指仍待继续。本文以下旧版本待办以本段与实际证据为准。

2026-10-21 最新验收（仅进阶本轮，不是整体目标完成）：Runtime129/CPU72/App182/Main46/GuestTools22/来宾工具V6/Dev169/Normal189 已在真实iPad独立27后端运行。来宾GUI工具实际UID501登录自动启动，真实HELLO后才同步；暂停完成state2、恢复完成state1均由原生回调验证。恢复后工具自动重新HELLO，无手动开关；22222认证、Apple HTTPS200、Unicode文字双向、合法2x2 PNG原生解码及往返后四像素RGBA比较均通过。UIImage/UIPasteboard会重新编码PNG，bytes相等不是内容相等：旧originalRestored=0是编码字节比较，专项原生像素与文字读回均为1。原生截图先黑屏（来宾显示已睡眠），实际Esc输入后完整桌面/设置恢复，未宣称物理三指/鼠标全量复验。固定摘要：normal189-native-pause-clipboard-final-proof-v1.json。

设置→通用“同步iPadOS剪贴板”默认开启，可关闭。支持有界文字、PNG/JPEG/TIFF、RTF/HTML/URL表示（本轮实际测试Unicode文字与PNG）；单帧编码最多4MiB、16项目；文件传输不在本轮范围。后台/暂停/关闭时停止新同步，停止VM时关闭自身监听；5秒HELLO和5/15秒保活防止旧连接残留。剪贴板内容不记入日志，原生字段只记录计数与布尔值。测试曾覆盖剪贴板，第一次旧测试脚本异常时原来内容恢复未证明；不要把后续已知样例的恢复等同于早期用户原内容已恢复。

仍优先待办：冷启动与壁纸/图标迟缓、CoreImage图标服务生命周期故障、CPU定时中断全局锁竞争、精确校时。3秒真实Normal188采样已定位PhysicalTimer→GIC全局mutex；GIC8/lifecycle68已是O2，不重复O2和泛化CI探针。clock17绝对时间在QGA排队后变旧，Normal189出现向后约10秒调整并读回偏差13秒；下一版应使用原生时间读样本/宿主中点偏差，再在执行时对来宾当前时间加偏差，并容忍小抖动，避免反复倒调。尚未实现，声音物理听感、麦克风、IPv6/桥接、GPU其余高级特性仍未全验收。beta2/V9保持冻结且未上传，用户明确暂缓发布。

2026-10-21 剪贴板双向真机结果：Normal188/App180配来宾诊断工具V4，固定中英文/组合字符/emoji和PNG已经在两个原生剪贴板间真实读回成功（normal188-clipboard-bidirectional-native-proof-v8.json）。测试脚本的JavaScript数组曾被桥接为NSDictionary，现已用实际NSMutableArray修正；早期测试清空了来宾剪贴板，首次测试原内容恢复未证明，不能宣称已恢复。旧恢复比较直接对比UIPasteboard.items对象得到0，后续App182改为逐表示类型的原始数据比较，尚待设备复验。

App182/Main46/GuestTools22已实际安装（Dev169，3自有文件1哈希，Runtime129不变），即将Normal189启动。来宾工具V6和宿主Bridge5加入5秒HELLO、5秒ping/15秒失活回收；只有实际HELLO后才发送剪贴板；工具安装完成后显式排空旧连接。Main46在真正启动完成后刷新暂停菜单，避免初建HUD时VM为空导致缺少暂停按钮。此次不进入冻结的beta2/V9发布快照，用户已明确暂缓上传。接下来先检验无需手动切换开关的登录自启动、双向复制与原生暂停恢复后的重连。

2026-10-21 剪贴板实测边界更新：Normal187 原生 vsock 连接建立，Root读回专属GUI LaunchAgent runs1/never exited、UID501、helper SHA bf8921b5…与预期相符。独立命令行iPad探针报PBError11，缺少UIApplication剪贴板上下文，写入读回0；因此它不是桥接失败证据，也不是真实恢复成功（该marker已在receipt更正为未证明）。探针已准确清理。App180已安装，换用App内固定文字/PNG有界原位测试、仅内存备份与恢复；GuestTools21还停止了缺失可选旧菜单包时每10秒的无效修复。完整同步与启动性能结论仍待实际结果。

2026-10-21 进阶开发更新：用户明确暂缓上传 beta2，V9包和158eba7本地源码快照保持冻结，未push/tag/发布。原生 Pause/Resume 已在 App176/Normal186 实机完成：真实 pause 回调 state=2、resume 回调 state=1、两次 verified=1，恢复后22222认证、DHCP/DNS/Apple HTTPS200再次通过。输入和显示恢复仍需当前设备完整交互复验，不能据此称所有高级生命周期完成。

剪贴板同步为用户新增必需项。App178/Main45/GuestTools19 已安装并在 Normal187 真正启动交接0；原生 VZ27 vsock505051 注册成功。设置→通用新增“同步 iPadOS 剪贴板”，默认开启；来宾专属 Aqua LaunchAgent 登录自动启动，Root只安装工具，实际读写由登录用户的 AppKit 进程执行。文字/PNG/JPEG/TIFF/RTF/HTML/URL有界传输，单帧最多4MiB、16项目；宿主作版本协调，避免回写循环和已知并发覆盖。后台、关闭开关、暂停时禁止新同步并关闭连接，不记录剪贴板内容。文件与文件承诺不在当前范围。双向文字/PNG、实际GUI自启动、设置关闭、暂停恢复后的重连均待实测，不能把编译及端口注册当成同步成功。

2026-10-21 正式包复验：2.0.0beta2/1002 最终安装包已在 Dev165 完成实际 dpkg 安装和全部265文件哈希、UID/GID、mode核验；运行库保留原700/600权限和私有0600 sandbox资源检查。Normal185 真正启动交接0，原生IOSurface首帧样本45秒，四CPU实际运行，22222认证、DHCP、DNS与Apple HTTPS200均通过。已由原生USB截图确认登录后壁纸、菜单和Dock完整；20秒仍淡出，冷延迟仍未修复。包与源码材料已备齐，私有GitHub目标仍待用户确认：当前origin为公开库，未上传。后续Pause/Resume的Main44宿主候选已编译，但不进入beta2快照，尚未设备签名或运行。

2026-10-21 发布准备更新：Runtime129/CPU72 已在 Dev158/Normal181 实机运行。App174/Normal182 加入原生输出音频及 Playback 会话，来宾实际识别 Apple Virtual Sound Device、2声道48kHz默认输出，afplay系统声音返回0；尚无物理听感证据。App175/Main43/Normal183 加入原生VZ27 FileHandle Ethernet与libslirp IPv4 NAT，真实DHCP获得10.0.2.15、路由10.0.2.2、DNS10.0.2.3并解析Apple域名，HTTPS返回200；独立vsock22222 SSH保持可用。正常关机停止回调已确认。网卡通过后按用户要求准备2.0.0beta2/1002，使用独立com.mac.virtual.independent27包，不发布到误识别的公开仓库；私有目标待确认。正式deb实机安装及启动复验进行中。

仍未完成：冷登录/完整桌面和图标冷生成延迟，CoreImage/RenderBox图标服务资源生命周期崩溃；精确RTC（避免数秒传输延迟造成倒调时间）；物理三指全场景；暂停/恢复、保存状态与GPU/其它设备高级功能；麦克风、IPv6/桥接。此前旧日期与图标修复声明以这些实际结果和顶部更正为准。Normal183真实完整壁纸/菜单/Dock/设置图标不等于所有冷路径已修复。

2026-10-21 实机进展：App171/GuestTools17 在 Normal180 登录前实际修正九天日期偏差：原QGA响应仅作返回记录，Root原生date读回与另一路SSH、0users均确认已校正，残余约9秒，RTC底层/精确校时仍未完成。Root自助登录20秒仍转圈；后续真实USB截图壁纸、菜单、Dock与设置图标完整，实际拖动/切换网络/原生退出再从Dock打开设置均成功，未据此宣称冷启动全修复。图标服务574 runs1/never exited。一次实际VMM短采样发现相同定时截止值仍反复提交。CPU72/Deadline2仅在原时钟/频率/所有者/代际/粘滞错误检查之后合并同值arm和重复disarm，触发后相同deadline重新arm仍提交；20055项真实dispatch回归通过，其中两万重复调用不再提交。其余28CPU对象、Main40/Surface9/GuestTools17不变，Runtime129/App172已签名，7自有文件4哈希准备Dev158安装。声音、真实NIC网络、硬件三指和冷启动图标生命周期根因仍待完成。

2026-10-21 时钟重要更正：Normal179/Runtime128/CPU71/App170/Dev156 真正启动交接0，首帧33秒，未作稳定提速结论。App日志显示clock16 guest-set-time成功且hostUnix1792529788=20:56:28UTC，但SSH在20:57:28及登录后21:02仍读到10月11日。故此前“接口success=1即已自动修正”的推断撤回，不能当成生效证据。Root原生/bin/date实际可修改，2秒走时持续，5分钟后仍维持新日期；该次脚本时间在密码提示前生成，实测约落后宿主21秒，不能宣称精确同步。

GuestTools17/App171已编译签名：保留原QGA45秒独占租约、代际及原SSH流程；原生guest-set-time只记录returnedWithoutError，随后在已确认guest-exec/status启用时运行一次Root原生date读取、发现偏差才用新鲜宿主UTC校正并再次读取。严格单标记与实际退出状态、当前宿主epoch漂移10秒内才记verified=1；verificationStarted与finish双重单次门避免同步失败重复执行。没有修改系统文件或保护。实际序列化脚本Root条件、printf真正换行及shell语法检查通过。仅GuestTools对象8替换，其余34App对象和Runtime128原样；1Main文件1哈希Dev157安装中，待Normal180登录前SSH验证真实日期。底层RTC仍待实现，不把这次QGA校正称为RTC完成。

2026-10-21 Normal178：Runtime127/App169未变，原生RIP_ENABLE_IMAGE_CACHE=false在图标服务单独域已写入并确认0，但仍出现两个真实崩溃：PID494 objc_release→MTLResourceListChunkFreeEntries→IOGPUMetalCommandBuffer完成；PID660 objc_msgSend→RB::Resource::set_volatile→prune_caches。该偏好已删除恢复原先不存在状态，不能列为修复。冷设置一次性任务已准确卸载删除。最早本轮USB截图已是完整通用图标及壁纸，实际登录先于Root密码输入，Root在秘密输入前取消额外登录，无密码键入；不据此计算无人值守登录耗时。Root随后真实点通用与拖窗，原生截图确认页面和窗口位移。

主机实现Mapping5：保留Mapping4所有native6所属线程/PID/token/epoch/已允许页/栈范围及读前后epoch检查，仅自然对齐2/4/8字节寄存器改为单次同宽volatile读，先暂存再验证epoch；其它大小与未对齐保留字节读取，写入不变。现有跨页/撤回/外部线程/PID/堆输出拒绝回归通过；CPU71仅替换1对象、28对象原样、155导出4依赖且零新增导入，调用来源修复仍在。Runtime128/App170已签名，7自有文件4新哈希待Dev156安装，尚未宣称实机收益。声音/NIC/硬件三指与图标资源生命周期根因仍待完成。

2026-10-21 Normal177 冷启动：四核 Runtime127/App169 实际首次画面39秒，60秒初始化交接0。无人值守登录20:19:56UTC，20秒仍有登录淡出；稍后真实壁纸、菜单、Dock完整。一次性设置任务20:20:58实际开始，20:21:11返回；图标服务505在07:21:06本地时间崩溃，栈CGSImageDataHandleRelease/图像缓存逐出/ISCompositor，重启783。原任务已准确卸载删除，暖重开完整不算冷修复。目录服务高ps百分比的一秒样本全在内核等待，不据此称CPU热点。

本轮临时FORCE_SOFTWARE_RENDERER GUI域环境没有被原生图标任务继承，不计渲染试验。TERM783未退出；准确KILL783一次后，普通launchctl start成功创建1545，但仍无该环境；临时域已unset，自有试验任务及全部文件已删除。停止继续环境继承试验，无SIP/系统文件改动。

读取当前来宾自身CoreGraphics文本与UUID38c8fbec-de88-33fe-b742-a192f22cc754，确认RIP_ENABLE_IMAGE_CACHE由原生偏好读取：环境之后，当前应用/当前用户/任意主机，再任意应用和com.apple.CoreGraphics域；原生缓存初始化消费bool。只读核查解析了实际CF常量/调用目标，未调用静态内部函数。真实图标可执行文件嵌入CFBundleIdentifier为com.apple.iconservicesagent。已备份并仅在这个应用域将RIP_ENABLE_IMAGE_CACHE写false，准备Normal178冷验证；此时尚无修复结论。证据normal177-actual-native-framework-text-v1、independent27-normal177-coregraphics-pref-contract-v1-attempt1、independent27-guest-normal177-icon-native-image-cache-trial-v1-attempt1。没有改其它应用偏好、图形框架或安全策略。

2026-10-21 后续实机更新：Runtime127/App169/Normal176 保持独立27运行。六核首帧49秒、两核34秒均未解决图标服务故障，已恢复原四核/8GiB。Normal172 的真实设置请求再次使图标服务崩溃，栈为 CFRelease/data_provider_finalize/CIAppleSmithGossettScale 析构；普通、相同滤镜、延迟绘图和真实应用图标客户端均未复现该故障，不再重复通用探针。仅图标服务偏好域的 METAL_ERROR_MODE=5 试验仍发生段错误，已删除该键恢复原先不存在的状态；没有应用全局覆盖。

通过来宾原生“墙纸→屏幕保护程序”界面把自定义红杉屏保改为“自动”，使其跟随已有 TahoeStill 静态图，并开启“在所有空间中显示”。系统保存的配置由 Desktop/Idle 分离改为 linked，提供者仅 image。Normal176 冷启动真实连接从05:42:25.172至27.741完成（2.569秒），05:42:37.500完成获取，距登录输入21.332秒；没有此前30秒连接超时。运行80分钟后实际只有 WallpaperImageExtension，没有 Aerial 扩展；GUI图标服务 runs=1、never exited。此时尚未重新打开设置请求其完整图标，不称为图标或开机整体修复。证据：normal176-native-wallpaper-actual-timing-v1.json。后续继续设置真实页面和输入/窗口响应，声音、实际NIC网络、硬件三指仍待完成。

启动检查已改为明确的60秒设备/55秒主机单调时间初始化，20秒后实际画面推进，保留原身份和ACK所有权交接；它不是长时间压力测试。Normal175、176实际交接成功。此前只改设备端时间而漏改旧主机285秒条件的Normal173被拒并准确清理；Normal174因未轮换自有日志而在启动前退出，之后已修正。iPad未重启。

2026-10-21 实机更新：Runtime127/App169/Dev155/Normal170 已恢复正常来宾执行、自动登录与交接0。此前Runtime126的广泛O2在启动入口内联16KiB检查函数，编译后栈探测调用早于LR快照，触发原生调用来源认证拒绝；Bootstrap29只追加静态noinline前置声明，保留原UUID/指令/路径/调用点校验。实际反汇编先mov x0,x30再首个BL，真实后续启动通过。其余CPU模块保持发布优化，首帧仍约38秒，不能宣称达到十几秒。

GuestTools16自动对时已在Normal168和170真实观察到guest-set-time advertisedEnabled=1、success=1；修正了九天日期滞后。降低透明度已用原生设置界面开启，defaults=1确认；原值0备份于normal168-reduced-effects-backup-v1.json，其他辅助功能选项未改。图标在暖状态完整，但早期空白和壁纸慢仍未整体验收。

Normal170图片扩展首次连接取消，重试17:42:31.518至31.755UTC迅速完成。其启动一秒时栈在ExtensionFoundation/BoardServices正常XPC主循环，尚未进入绘图；spindump也出现处理卡顿，可能干扰冷启动，停止继续启动期采样。下一步只以普通6-vCPU配置和干净启动比较改善拥塞，原4核已保存，仅CPUCount准备改变，8GiB内存及其余配置原样。声音/真实NIC网络/硬件三指等仍待完成。

2026-10-21 当前实机：Runtime125/App166/Normal167 的 native C1 PAC key 批处理已实际执行，首8组均4次写入/4次回读完成，155导出4依赖、无新增导入，其他27个CPU对象原样。只对真实Production回调合并连续密钥写入；native8寄存器组同步、密钥值/顺序、逐项回读、前后owner/epoch/token/version、普通回调逐字段路径保留。首帧观察34秒（前轮39秒，非受控测速）；设置空白图标与冷壁纸问题仍复现，不认定修复。

Normal167：校正来宾落后九天的日期后，自动日夜外观刷新使设置完整图标重新出现；这是暖状态重新请求成功，非冷启动验收。真实GUI IconServices应用/文档/符号图标64px和512px共8次返回非空像素；一次性自有job已卸载。自有来宾工具Dock修复版本已为3，排除本轮反复删缓存。原生GPU样本均真实完成status4，无已记录错误。两轮冷服务采样因符号解析超时无可用栈，不计成功证据。

App167/GuestTools16已签名：在真实guest-info中确认guest-set-time启用后，以宿主NSDate发送一次标准纳秒时间，保持原QGA45秒租约与代际检查，完成/失败后只继续一次原SSH/桌面流程；缺失命令明确暂缓。单文件单哈希Dev153待安装/冷启动核查，Runtime125原样。当前用户重点仍为启动迟缓、图标/壁纸冷加载、拖动流畅度；硬件三指尚未确认，声音/真实网络NIC及宿主RTC底层实现继续列后续，SIP/iPadOS系统文件不改。

2026-10-21 最新实际结果：Runtime123/App164 的 Normal165 正常交接与自动登录0；输入提交16:07:29UTC后20秒画面仍只有菜单栏和深色背景。图片壁纸扩展第一次连接超时并触发30秒失败，之后重试连接和实际创建约1.44秒完成，证明还存在冷启动服务就绪延迟，静态图片不是完整修复。后续真实点击设置看到完整彩色侧栏，GUI图标服务521本轮runs=1从未退出；此为本轮观察，不代表早期冷加载已修复。arm64e四线程CoreImage共享context，软件32次、真实Apple Paravirtual GPU32次生成/读取/释放均完成，无故障复现。

Runtime124/App165 已签名：只在真实CPU创建成功后的同一所属线程请求普通QOS_CLASS_USER_INITIATED，原DEFAULT/UTILITY/BACKGROUND可调整，UNSPECIFIED或更高优先级保留；精确CPU成功销毁后恢复原选择，原HV结果与errno不变，Run路径没有新增调用。原Factory12经SDK预处理后的主体tokens保持（仅两公开定义改为隐藏原入口并追加同名薄包装），其它28CPU对象原样、155导出4依赖、零新增导入；待实机日志验证是否实际接受。Dev151安装中，未宣称速度改善，未改SIP或iPadOS系统文件。

2026-10-21 新版准备：Runtime123/App164 已签名，CPU只把现有Factory12原样源码以-O2 -fno-strict-aliasing重编译，其他28对象原样、155导出4依赖、零新增原生导入；不包含尝试但未编译成功的QoS草案，不改变线程调度/优先级。Normal164三秒VMM采样实际CPU9.832秒，热点中Factory的版本/对象范围/结果检查仍显著。Normal164已正常关机并准确清理，Dev150七文件四哈希安装中，实机收益待测。

图标归档兼容试验不计为通过：SIP阻止debug/kickstart；同用户TERM和GUI重开可执行，但实际iconservicesagent环境未观察到CI_DISABLE_LOADING_ARCHIVES，临时用户环境已还原，自有GUIjob均卸载。停止这类环境试验，继续底层图像/并发生命周期定位。静态PNG已通过原生API设为Desktop image provider并实际可见，下一次启动会复测；Idle仍Sequoia。

2026-10-21 实机补充：App163/Dev149 单主程序单哈希已安装0，Normal164自动登录在未显示旧键盘时成功，正常交接0。本地红杉扩展首次失败并回退Aerial，未解决等待。已从原Aerial视频真实提取2732x1536 PNG（guest Pictures/VirtualMacCompatibility-v1/TahoeStill.png），用一次性普通用户GUI启动项调用原生NSWorkspace设置壁纸，返回YES，实际配置Desktop provider变为com.apple.wallpaper.choice.image，USB截图已显示TahoeStill缩略图及背景。原配置备份在guest Library/Logs/VirtualMacWallpaperOnce-v1/Index.plist.before（SHA8ac783d...），自有GUIjob已卸载。Idle仍为Sequoia，下一轮启动收益待验收。

图标侧栏仍大量空白。CoreImage原生字符串确认CI_DISABLE_LOADING_ARCHIVES选项存在；尝试launchctl debug和kickstart均被来宾SIP拒绝150，未关闭SIP。CI_ENABLE_METAL_GPU=0在自有显式GPU小测试中返回nilcontext，不可部署。当前准备普通同用户TERM/原生重开图标服务和Settings的一次性归档兼容测试，短暂用户环境立即恢复，无系统文件修改；尚无图标修复结论。

2026-10-21 输入所有权补充：Main39 的 HUD/URL/外设与回前台入口仍可能将第一响应者转到旧 gInputView，而该视图的旧软件按键函数在独立27模式明确不发送。App163/Main40/Surface9 已在主机编译签名：这些入口统一选实际独立输入 Surface；收起屏幕键盘改用空 inputView，保留真实第一响应者及外接按键路径。仅两个App对象变化，Runtime122不变，实机验证待进行。Normal163 的真实 who 证明自动登录最终成功，但20秒截图仍停在登录页，不能把该截图视为登录失败；该轮登录后负载25/59，DNS失败（当前独立启动配置明确 networkDevices=0，SSH为独立vsock通道），日期仍落后9天。待基础图像故障解决后补网络与时间同步。

2026-10-21 最新主线：Runtime122/App162 实际部署 Dev148，7文件4哈希，Normal162运行交接0，Root自动登录成功。首帧观察到40秒（前轮43秒，非受控收益）。壁纸扩展连接21.254秒，首播放器约9.853秒，仍非十秒可用。GUI iconservicesagent 本轮3次crash后新实例847继续服务；Root自行点击设置Dock后实际看到完整彩色侧栏图标，但启动失败仍需修复。

两份 Normal161 当前图标崩溃中，CFRelease 的 x0 分别为页对齐0xa5929d000/0xb4b273000，加载的首字均为0x28001424c544d，低字节明确是 MTLB Metal库文件头（4d544c4201800200），而非正常对象ISA。证据位于 normal161-icon-crash-metallib-header-evidence.json；不能通过跳过PAC校验当作修复。真实系统 GenericApplicationIcon.icns → CIImage → Lanczos/Blur → CGImage→强制CopyData后释放，软件与GPU各8次都完成；该同步小样本未复现实际异步图标请求。

已备份原Wallpaper Store/Index.plist，原生设置UI已选择本地“红杉·浅色”，provider为com.apple.wallpaper.choice.sequoia，避免Aerial视频路径；不是已证实的image still provider。启动收益待实测。此为明确的可选功能兼容方案，不能称为VideoToolbox已实现或图标服务崩溃已修好。截图快捷键自动回归未能触发iPad编辑器，不能称为通过。用户无需继续配合点按。

2026-10-21 当前继续：iPad 截图编辑器的主线程真实等待 sharingd，再等 SharingXPCHelper；后者启动线程停在分配器锁，持锁线程显示 suspended。来宾正常关机后截图仍卡住；保存全系统等待链后只结束已核实的截图编辑器和该按需辅助进程，未重启 iPad、未改系统文件，用户确认主屏幕恢复。App161/Main39 已部署：失去前台及进入后台时删除自有手势所有权标记，返回前台且实际显示来宾时恢复；原输入暂停/恢复保留。此边界修复不能替代截图辅助进程卡死的回归验收。

Normal161 实际登录后多分钟才有壁纸，设置侧栏大量空白图标。直接日志将 System Settings 的图标请求 4097 与 GUI iconservicesagent675/865 的崩溃关联。两份当前报告在 CFRelease+64 的真实 AUTDA x16,x17 指令（指令字 dac11a30）触发 PAC_EXCEPTION，调用链经 CoreGraphics data_provider_finalize / CoreImage 图像和 CIFilter 释放；不能把该指令字当作坏指针地址，也不能仅据此认定 CPU 密钥错误。旧报告还有 Metal 完成队列 objc_release 无效地址。普通用户有界 64x64 CoreImage 生成/释放对照，软件和实际 Apple Paravirtual device 各12次均完成；尚未复现真实图标崩溃，不宣称该问题已修复。

用户已明确授权后续无人值守点击、登录和必要 Root/新增哈希；当前横屏已用两点原生 USB 图像校准逆180度映射。Root 实际点击关于本机成功、窗口拖动有画面记录，不能替代开机阶段响应验收。Runtime122/App162 主机已签名：仅 System6 的精确156字段并集常量查找与O2代替旧线性查找，其余28个CPU对象保留；2,162,787次与旧谓词一致。Normal161已正常关机，正在部署，性能收益尚未实测。声音与网络等完整功能排在这些主要可用性问题修复之后。

# 独立 macOS27 后端：基本启动优先与后续实现

2026-10-20 延迟主线继续：用户反馈 App151 仍有迟滞，不视为修复。Normal153 三秒宿主 App 采样中主线程301次均在事件等待，App总CPU时间0.010秒；此为空闲阶段样本，不能证明实际移动时无延迟。Dev141 已实际安装 Runtime118 / App153：仅扩大既有同属CPU上下文映射加速的字节上限16KiB到32KiB，覆盖原Run路径真实0x4118读取；逐页权限、所属线程、原Mach回执、外部线程回退和native7前撤销均保留。App增加每类最多64条真实指针/光标时间记录，保留已确认的输入语义和显示13；Normal154 正在启动，性能效果尚未验收。


2026-10-20 用户补充：二指滚动和三指滑动仍未实现，不得以二指副按钮点击可用替代手势验收。当前优先顺序仍为卡顿、启动后桌面长时间不完整、拖窗掉帧和指针延迟；随后补齐二指滚动及三指窗口/桌面手势。现有 basic input 配置的 pan/pinch/rotation 识别仍关闭，不能宣称这些交互已提供。


2026-10-20 Normal152 实机输入确认：App150 的触摸、Magic Keyboard 左键和两指右击，用户反馈“操作基本正常”，但指针仍有延迟；启动/桌面就绪和拖窗掉帧仍未完成。Runtime117 保留实际四 CPU 执行。App151 仅替换显示对象16，将原生 IOSurface 的每帧完成后固定1/60秒等待改为主队列异步合并；仍由真实 CA 完成后确认原帧并保护前后 surface，不改变任何输入对象。此版本已在主机编译签名，Dev140 尚未执行，延迟改善仍需实机检查。


2026-10-20 输入回归跟进：用户在 Normal151 报告触摸移动失效、解锁卡住，仍不能判定完整鼠标控制已修复。已定位副按钮适配中将 End 事件非零 mask 保留为按住，以及 allTouches 中停留的 indirect touch 优先于直接手指的问题。App150 仅改两个输入对象：End/Cancel 明确释放同一 UIKit contact；Began 没有按钮位时保留正常 primary 语义；手指快照排除 indirect touch，并在从外接按钮转给新手指前通过真实原 sender 释放原按钮。CPU/运行库不变。新版本正在安装，尚待实机确认。


2026-10-20 当前修复状态：Runtime116 / App148 的 Normal150 已在 iPad 上正常登录；用户实机确认 Magic Keyboard 按住移动可以拖动，来宾区域的 iPadOS 圆点已隐藏，显示真实来宾指针。用户随后确认两指副按钮仍不可用，启动迟缓、桌面完成迟缓和拖窗掉帧仍在，因此这些项目继续属于当前主线。来宾 SSH 在本次启动后已再次通过 iPad22222 实际认证；永久启动项保留。Terminal 的 `ShowTerminalInDockIcon=false` 临时尝试未恢复空白 Dock 图标，已经删除该键以恢复此前不存在该键的状态，不作为修复。副按钮和稳定 CPU 所属线程元数据优化已合入 Runtime117 / App149，Dev138 已备份后安装，Normal151 正在启动；右击与速度效果尚待实机确认。输入队列显式保留真实 UIKit primary/secondary/第三按钮状态，继续使用真实 macOS27 指针事件发送；CPU 仅对实际所属线程、持有操作保护及存活的注册句柄复用稳定元数据，跨线程和销毁仍保留原锁与检查。


Dock 图标问题更正（用户新说明，2026-10-19）：用户明确指底部 Dock。放大 Normal147 原生截图后，在最近使用区域 Weather/Notes 后、Downloads 分隔线前确有一个空白运行图标，仅剩黑色运行圆点；此前“Dock完整”的判读不准确，不能以 Finder 18图标齐全替代 Dock 验收。对应应用身份尚未证实，仍需在当前 Normal148 中优先定位和修复。更正证据：`independent27-normal147-basic-use-evidence-v2-attempt1/result.json`，原始截图保留。

Runtime115 / App146 后续优化（2026-10-19）：Normal147 已实际登录，执行新的 `echo native27` 得到返回，完整原生 USB 截图中 Finder 18个可见应用图标正常，Dock仍有一个空白运行图标（见顶部更正）；首次恢复应用仍慢。四 CPU 的真实映射缓存均已采用，首次帧日志约139秒，前次约239秒，属于非受控单次样本。又对实际慢阶段的自有 VMM 进行一次三秒原生采样，定位计时器的重复固定系统信息查询和六次共享页 Mach 查询/复制。Counter22 保留完整 V21 诊断接口，将正常回调改为逐次读取真实共享页六字段、计数器和绝对时间，仅在进程内缓存经核实的固定硬件/内核身份及 Mach 换算比。只替换一个 CPU 对象，其余28个保持原样，所有图形修复和146份权限保留。已通过编译与本地边界检查并签名，Dev135正在安装；实机速度和本版图标验收仍待完成。Normal147 已正常关机，实际停止回调及原stop/post均为0，iPad未重启。

Runtime114 / App145 当前安装状态（2026-10-19）：Dev134 七阶段实际返回均为0，已安装到 iPad。根据真实 VMM 原生三秒采样中发现的重复自进程映射查询，CPU 后端仅替换三个对象，其他26个对象保留。新映射缓存限于实际 native6 创建后核实的上下文页和同一线程栈，native7 前撤销；其他地址和原始回执仍执行真实 Mach 查询。原生 CPU、GIC、计时器及图形修复保留，全部146份现有权限不变。Normal147 正在冷启动；尚未取得这个版本的登录、图标或速度验收，不能宣称优化幅度。

当前验收目标是：iPad 上运行真实来宾，全部使用独立 macOS27 Virtualization/VMM 与自有 CPU 后端，能够看到画面并使用基础键鼠。按用户最新要求，22222 端口及 lkx 登录在来宾启动成功后继续，除非启动故障排查需要。框架加载、CPU 创建或测试通过均不等于完成。

2026-10-19 当前进展：Normal144 / Runtime109 / App140 已在 iPad 原生 USB 截图中显示清晰桌面、Terminal、Finder 内容及 Dock，旧彩条和黑块未再出现。实际 Cmd-N 后执行 `echo vm27` 得到 `vm27` 返回。关键修复是将原生实测支持的 framebuffer fetch 能力正确提供给原版 macOS27 图形消费者；独立原生 Metal 探针已实际验证 256 个像素的读改写。GPU 的两处可选 Volatile 缓存丢弃保持暂缓，真实资源释放和完成链保留。本次日志没有新的来宾 panic 或 VMM 致命信号；桌面仍显示旧崩溃报告提示，未向 Apple 发送报告。

Normal144 中切换现有原生 IOSurface 图层后，真实 CA 事务完成，原生 USB 截图仍清晰。随后已正常关闭来宾，完成原租约 stop/post。Dev131 已安装 Runtime111 / App142：默认原生 IOSurface，移除全帧 CPU 复制及固定 100 毫秒调度延迟，改为按 1/60 秒合并更新；关闭仅用于此前排错的 GPU 子进程 Metal 调试层，保留全部已验证图形兼容修复、29 个 CPU 对象和原始键鼠通路。Normal145 已实际冷启动并登录到清晰桌面，新的 Terminal 正常执行 `echo native27`，快速键入与后续窗口重绘有原生 USB 截图证据；临时键盘通道已准确清理，来宾继续运行。登录及应用恢复过程的一次实际样本，在 20 秒内从 5797 推进到 6327 次真实原生 CA 呈现完成，约 26.5 次/秒，CPU 整帧复制为0，新增匹配致命错误记录为0。这不是物理屏幕刷新率或空闲桌面基准，不能称为实测60 fps。启动和应用恢复仍偏慢，CPU/磁盘路径性能继续列为后续优化；下文旧版本状态作为历史记录保留。

SSH 后续状态已更新：原生 sshd 和自有 vsock 辅助程序已永久启用，启动项随来宾开机运行已在后续冷启动中实际验证；iPad 回环 22222 的真实 VZ 桥在 App 启动来宾时创建。当前仅用于框架故障排查，不再重复安装 SSH。

Normal145 后续发生新的阻塞：点按检查期间，自有 VMM 捕获 SIGSEGV，fault address `0xd1`，随后原生 `didStopWithError` 确认意外停止。原始 LR 去除 PAC 后为 `0x100ff23ac`，主程序基址为 `0x10066c000`；两者差值 `0x9863ac` 超出主程序代码范围，必须先确认调用者实际属于哪个运行库，不能沿用旧崩溃的 VMM RVA 推断。当前来宾已停止，正在优先修复；此前清晰桌面、真实终端命令和原生呈现速率证据不等于稳定运行验收完成。两次远程点按未形成有效横屏校准，不得宣称任意点按或拖拽已验证。

随后用现有 `true` 命令的独立加载日志取得当前原生共享缓存地址，未安装新探针、未增加权限。实际 PC 正好是原生 `xpc_connection_set_oneshot_instance` 的函数入口，x0为空。原版 PG 在 RVA0x363a8 调用此函数，之后才检查初始化失败；真实 LR 与该返回点一致。Runtime113 将空连接检查提前到原生调用之前，只改四个指令字，空值沿原有释放对象并返回 nil 的分支处理；非空值仍调用真实系统函数，原有 SP、FP、LR、PAC 与栈展开不变。MD32 只补充实际 GPU 工厂失败原因记录。App144 的 Display11 将原生帧日志改为前四次及每128次抽样，保留每一帧真实完成后的 ACK 和原生显示调度。Dev133 已实际完成七阶段安装与初始化，全部为0，全部146份权限保持不变；Normal146 正在重新启动，修复后的稳定桌面和晚期 GPU 创建仍待实机确认。

Normal146 当前实际结果更新（2026-10-19）：Runtime113 / App144 已登录到清晰桌面。针对本次横屏，使用两个安全角点、iPad 原生 USB 截图和来宾实际 CGEvent 指针坐标交叉确认远程注入需反转两个坐标轴；随后准确点击“忽略”关闭旧报告提示，准确聚焦终端，实际清除旧输入并执行 `echo native27`，得到新的 `native27` 返回。正常打开 Finder“实用工具”后，18 个应用图标均可见；实际拖动窗口后，图标、窗口内容和 Dock 仍完整，未见旧花屏。临时输入服务与本地代理均已准确清理，运行租约继续保留来宾。

本次启动恢复应用过程仍慢。来宾只读检查曾见一分钟负载289.62；随后两个此前占用高的服务采样已处于正常 Mach/工作队列等待，不能据此认定死循环。负载之后实际降到1.42、0.60；最近一次 `iostat` 短样本 CPU 空闲98%。不能把登录后空闲样本称为启动速度或高负载性能已优化完成。用户新增的“图标消失”仍按主线跟进：目前同次运行的 Finder 18图标、Dock 及拖动重绘未复现，已询问具体发生位置。桌面目录读取受来宾现有隐私权限拒绝，不据此认定目录为空，也未更改 TCC 或清除缓存。Finder 现有偏好为不在桌面显示内置硬盘（0），未擅自改动偏好。后续继续按实际消失位置定位，不将一次图标齐全画面称为所有图标问题已解决。

同次运行又通过实际点击进入“应用程序”文件夹，首次画面有计算器、家庭、快捷指令、密码、日历、时间机器、时钟等虚线占位图标；稍后原生 USB 截图中全部可见图标已自行加载完整。再次点击返回、前进后，缓存图标仍完整，未再次出现占位。该现象目前证明首次生成有延迟，不证明存在持续丢失，也不证明首次加载性能已修复。来宾图标日志有 named-image 查找失败/私有属性 EINVAL，但随后真实图标成功，不能把这些日志直接定为根因。没有清理图标缓存、更改 TCC 或关闭系统服务。正常桌面、实际终端输入、点击、拖窗和图标重绘已经有同次运行证据；主线基本启动与操作已达到，初次图标加载和启动速度仍可继续优化。证据汇总：`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/independent27-normal146-basic-use-evidence-v1-attempt1/result.json`。

后续可暂缓项补充：完成真实资源使用期同步后恢复 Volatile 缓存回收；完善长时间运行的帧诊断日志采样与轮换；扩展尚未实现的 AMX、外部 USB、非基础多媒体及其他可选 macOS27 能力。基本可见桌面、输入和正常来宾运行优先。

截至 2026-10-18，Runtime86 / App104 已通过 Dev89 七阶段实际安装与初始化，全部返回 0。主线使用独立 macOS27 框架及自有四 CPU 后端，Main32 保留原始 boot-args 与 recovery=false，未切回 macOS13。Production10 已实际核实四 CPU 上下文与线程栈的有界读写加速准入，Runtime86 仅对源码不变的三个 CPU 热点对象启用 -O2 -fno-strict-aliasing，其余 26 个对象保持不变。Normal106 在约 289 秒完成第一张真实 2732×2048 位图，Normal107 在约 214 秒完成第一张；Normal107 运行到 900 秒仍只有一帧，未达到可用验收。随后定位到显示适配器缺少原版消费者调用的 presenter 消费确认：原生产者会等待同一 observer 的 ready 标志，再发送下一帧。App104 只重编译 observer 与 bitmap 两个对象，将原函数的消费确认接到真实位图发布完成之后；真实空画面更新会完成清除事务后确认，且不计为位图帧。其余 33 个 App 对象（包括 Main32 和 Runtime86 anchor）、运行库及所有 CPU 对象不变。修复已完成单文件安装。Normal108 已连续完成 373 张真实位图，并完成运行所有权交接，但原生截图仍为黑色，不能称为来宾已可用。随后已正常停止并核实退出。App105 / Dev90 仅更新主程序，七阶段实际结果均为 0；Normal109 连续完成 405 张真实位图，但前四张复制位图的全部 RGB 均为零，原生画面仍黑；来宾实际已进入 macOS 26.6.2，WindowServer 与 loginwindow 存在，Finder/Dock 未启动。运行已正常停止并核实退出。USB 实时日志进一步捕获原版 PVG 的 Invalid task；当前包缺少原版 PGRemoteTask 所要求的 GPUTask 服务。该服务属于基本图形启动必需项，已恢复为当前主线。新原版 macOS27 GPUTask 已实际完成移植、严格链接、原生导入闭合及签名，正在接入自有受认证端点；尚未部署，不能称为 GPU 修复成功。软件键盘 UIKeyInput 和代理普通非零退出处理已编译进 App106，待与新运行库一并安装；SSH 转发继续暂缓。磁盘完成链观察器仅有 HOST 源码，尚未编译或部署。

Runtime91 / App111 已通过 Dev97 七阶段实际部署与有界初始化，全部返回 0。GPU 服务的动态库加载拒绝由真实 can-execute-cdhash 权限修复；随后实测发现 dyld 第 0 项是动态库，已改为按固定 GPU 程序完整路径唯一查找，再执行完整的执行镜像、UUID、LC_MAIN 和入口指令核对。实际短检查已找到第 1 项的正确执行镜像并通过上述校验及真实 no-sandbox 权限核对，随后按缺少控制端点的预期返回 57。另为实机缺失的三个可选 Metal BOOL 能力查询提供精确调用点适配，原生存在的方法照常调用，缺失能力返回不支持；原 RGB 分类、跨平台库调用及 GPU 命令保持原生。29 个 CPU 对象及 34 个 App 功能对象不变。Normal113 实际连续生成 380 张位图，但原生截图仍为黑色，GPU 握手在共享内存解码时失败，随后已正常停止并核实退出。原生 GPU 握手、可见画面及基础输入尚未完成验收；SSH 继续暂缓。

Runtime92 / App112 已通过 Dev99 七阶段实际部署及有界初始化。Normal114 的真实映射记录确认：第一段 10 MiB 共享内存映射成功，第二段 8 GiB 来宾 RAM 的 xpc_shmem_map 返回 0；原生完整长度比较和错误返回均保留。随后 Runtime93 / App113 / Dev101 仅为 GPU 子进程补齐扩展虚拟地址空间权限；Normal116 实际确认两个 GPU 子进程均完整映射 8 GiB 来宾 RAM，且找到真实匹配的 Metal 设备。原生画面仍黑，实际崩溃报告进一步定位到 Task RVA 0x4ea20 的 IOSurface 纹理分配：Managed(1) 存储模式被 iPad Metal 拒绝。Runtime94 / App114 / Dev103 的实际 Normal117 已确认此调用三次返回真实非空纹理，原生分配和校验保留。截图仍黑；日志进一步显示渲染管线创建失败及私有 scheduled-event selector 缺失。Runtime95 / App115 / Dev105 已完成实际部署，Normal118 已通过 GPU 加载、完整 8 GiB 映射和真实 IOSurface 纹理分配；新 NSError 观察器的大栈触发编译器栈探测调用，导致随后捕获的返回地址不再是原 Task 调用点，被原校验拒绝。Runtime96 / App116 / Dev107 已将诊断缓冲区移入独立函数，实际 Normal119 已通过精确调用地址校验并取得原生错误：AGXMetalG14G code=3，Function A2Xhcu 使用 Metal 语言 3.2，与 iPadOS 16 不兼容。当前优先追查宿主到来宾的真实 Metal 语言版本协商。原生截图仍黑，尚未达到可见可操作验收。Normal118、Normal119 均已正常停止并完成产品及 OFF 核对。Main33 随后通过原版 VZ 配置接口选择 2022 图形能力档位；Normal120 已实际读回 level=1，原生 PG 将来宾协议 245 限制为 62。来宾仍黑，实际 GPU 崩溃栈定位到另一个 IOSurface 调用 0x4e490，Managed 存储模式仍被拒绝。Runtime97 / App118 / Dev109 已实际安装；Normal121 已确认此前失败的 0x4e494 调用三次返回真实非空 Shared 纹理，随后遇到 iPad 原生采样器缺少 setReductionMode: 的错误。Runtime98 / App119 / Dev110 已实际安装；Normal122 已确认原生默认 WeightedAverage=0 得以保留，非默认模式在原生不支持时仍明确失败。由于 Normal120 在管线创建前崩溃，尚不能确认着色器版本问题已解决；Normal120 已正常停止并完成产品及 OFF 核对。Normal116、Normal117 来宾均已正常停止；Normal117 重拉起的自有 UI 也已准确关闭并完成产品/OFF 核对。

Normal122 已通过上述纹理和采样器调用，后续原生 shader 编译未报告此前的 Metal 3.2 管线错误；但尚不据此宣称全部着色器兼容。显示消费者持续完成，原生 USB 截图中可见来宾彩色等待光标，桌面仍黑。一次 20 秒、最多 1 MiB 的外部只读自有 VMM RAM 诊断已通过同次运行的真实 RAM 映射、页表、KC UUID 与 slide 校验，取得 174 个结构校验过的来宾进程，包括 WindowServer、loginwindow 和 AppleQEMUGuestAgent。来宾内核日志反复报告 AppleParavirtGPU hang：部分 Memory/Object 队列推进，Exec 完成计数停在 0x904600，Display 等待后续 Exec 完成。因此 GPU 命令与 FIFO 完成通知已恢复为基本启动主线阻塞，不能继续归类为可延期优化。Normal122 已精确停止，stop/post 均为 0。下一版只读记录真实 command buffer 的调度、完成、错误与真实事件值，保留原生 commit 和现有 signal 行为，再据实修复。

Normal123 已实际确认前六个执行命令缓冲区完成、真实共享事件达到目标值且没有 NSError，但来宾仍报告 Exec 队列停滞。Normal124 进一步确认前五个成功 token 均已送达原生 VMM，且原生完成方法已返回；截图仍黑，不能据此前几条成功推断整个 GPU 完成链正常。两次运行均已精确停止，stop/post 均为 0。Runtime101 / App122 / Dev113 已通过实际安装及有界初始化，正在 Normal125 中观察原生回写命令缓冲区的调度、完成与错误，以定位后续写资源分支。此版保留 Main33、CPU29、原生资源复制、commit、完成回调与事件值；未把事件或 stamp 写入当作完成。

Normal125 后续实际完成数超过 32768，原生 FIFO 线程也在处理新命令与 DisplaySwapMapping，故前几条日志不能用于判断已经立即死锁。随后同次运行最终仍报告两个 Exec37 未完成；完整原始日志和 PID64222 原生崩溃报告给出直接原因：普通 createNormalTexture 的 Managed 存储模式被 iPad Metal 拒绝，GPU 子进程退出并重启。此前三个 IOSurface 创建入口的适配没有覆盖普通纹理创建。当前主线改为补齐四个同 selector、同三参 ABI 的精确调用点；事件调度逻辑没有据此更改。Normal125 stop/post 均实际为 0。WindowServer 与 loginwindow 的有限只读线程诊断通过身份及布局校验，但没有可用内核栈，不据此宣称获得有效回溯；来宾仍未达到可见可操作验收。

Normal126 已在 Runtime102 / App123 / Dev114 中实际通过此前崩溃的普通纹理路径：Managed 描述符在真实统一内存设备上复制为 Shared，原生返回非空纹理；命令缓冲区完成记录推进到 131072，真实事件计数和原生 token 完成通知也继续推进。原生截图仍黑，不能记为桌面已可用。本轮只读来宾 RAM 检查取得 WindowServer、loginwindow 和 SecurityAgent，尚无 Finder/Dock；两次读取的内核末尾日志没有捕获此前的 GPU hang。三次中央短触摸令 iPad 软件键盘收起，但没有可见来宾指针响应，坐标校准仍未通过。随后为读取登录及窗口服务的实际错误，已准备 App124 的固定只读 QGA 诊断入口和后期有限 RGB 统计；只重编译 Main、GuestTools、bitmap 三个对象，Runtime102 与其余 32 个 App 对象保持不变。Normal126 stop/post 均实际为 0。基本画面和输入仍是主线，SSH 转发继续暂缓。

Normal127 的固定 QGA 图形诊断已实际获准执行，但在 45 秒操作上限结束，返回的 157 字节是本地取消说明，不能当作来宾输出。该轮已准确停止，stop/post 均为 0。App125 / Dev116 仅重编译 Main35 和 Display9 两个对象，实际七阶段均为 0，Runtime102 与其余 33 个 App 对象不变。Normal128 已完成真实运行所有权交接；同次运行通过严格 URL 切换到 IOSurface 原生 CALayer，真实事务完成后确认消费，但原生 USB 截图仍只有黑色和等待光标。因此切换显示消费者未解决桌面阻塞。实际 GPU 命令完成继续推进至 131072，QGA 仍能返回等待桌面会话的真实退出码 75。一次 Shift 按下/释放未恢复画面，不能据此认定键盘已可用。此轮已精确停止；自动重拉起的自有 UI 导致标准 post=8，按实际新 PID 准确关闭后恢复检查为 0。App126 / Dev117 的单 App 文件更新已实际完成，七阶段均为 0，仅重编译 GuestTools 一个对象，Main35、Display9 在内的另外 34 个对象及 Runtime102 保持不变。Normal129 正在启动，使用精简后的固定进程查询、1 秒 WindowServer 采样和有界真实执行状态日志，继续定位桌面阻塞；不扩大可选框架实现。

Normal129 的一次诊断在 45 秒结束且没有取得来宾输出，已准确停止并核实退出。App127 / Dev118 的单文件修复实际七阶段均为 0，仅重编译 GuestTools，保留 Main35、Display9 和 Runtime102。Normal130 实际完成运行交接，并成功取得 507 字节来宾启动诊断：系统版本 26.6.2，初始设置标记存在，WindowServer、loginwindow 与 AppleQEMUGuestAgent 正在运行；控制台 UID 88 对应 WindowServer，不能称为已登录用户桌面。原生截图仍黑，固定图形诊断在 45 秒内没有完成；真实 pending 响应的累计输出字段已得到验证，但外层 head 缓冲仍挡住未完成诊断的前段输出。随后已准确停止，stop/post 均为 0。App128 已实际编译及签名，仅修改两段固定诊断脚本的逐行有界输出与阶段标签，正在部署；不据此宣称修复图形启动。一次原生 VMM 采样中 CPU 大部分采样处于等待，暂不以未证实的性能猜测改动 CPU 或磁盘策略。

App128 / Dev119 实际单文件部署及有界初始化七阶段均为 0。Normal131 已完成真实运行交接，并在同一来宾中实际取得 16 KiB 固定登录诊断：WindowServer、loginwindow 与 SecurityAgent 均在运行；WindowServer 的 1 秒采样中主线程及显示、渲染、虚拟显示、HID 线程在等待消息，未见 GPU fence 等待。原生截图仍黑且屏幕键盘遮挡下半部，不能称为登录界面正常。逐行诊断修复已实际保留一次超时前的控制台及进程查询阶段输出。下一步转向 loginwindow / SecurityAgent 的真实等待路径，并准备仅由明确诊断入口触发的现有 SSH 服务，作为框架故障排查工具；默认基本启动仍延后 SSH。CPU 维护开销的短采样显示锁竞争，尚未据此修改 CPU 或将其归因为黑屏。

App129 / Dev120 已实际完成单文件部署与有界初始化，七阶段均为 0；仅重编译 Main36，保留 GuestTools14、Display9、Runtime102 和其余 App 对象。默认启动仍延后 SSH，明确诊断 URL 才能提交一次现有桥接及服务启动。Normal132 已实际完成运行交接，但诊断桥创建返回 EADDRINUSE(48)，没有启动来宾 SSH 服务。实际查询确认占用者为旧版自有 com.mac.virtual.guest-ssh-proxy 作业，重启后恢复监听 22222；已核对原 plist 与进程身份后仅运行时 bootout，plist 不变，重启会恢复。Normal132 stop/post 均为 0。当前以同一已安装版本启动 Normal133，继续直接排查登录进程；尚未取得 SSH 认证或可见可操作来宾的验收证据。

Normal133 已实际确认桥接注册成功，但原 SSH 服务的 120 秒 QGA 等待结束时尚无代理连接，因此没有启动来宾 SSH 服务。随后只读 RAM 检查取得 AppleQEMUGuestAgent、WindowServer、loginwindow；同轮后期 QGA 已真实连接并返回等待桌面会话的退出码 75。原版 VZ 监听器按端口分别保存，没有找到新监听器覆盖旧端口的证据。为直接取得登录阻塞，App130 / Dev121 已实际安装，七阶段均为 0；仅重编译 GuestTools15 的固定只读脚本，采样 loginwindow 与 SecurityAgent，保留原 45 秒操作上限及超时前逐行输出。Main36、Display9、Runtime102 和其余 34 个 App 对象保持不变。Normal133 stop/post 均为 0；Normal134 正在启动，暂不再启用诊断 SSH，来宾画面与基础输入仍未完成验收。

Normal134 已在同一 Runtime102 / App130 中实际完成运行交接，独立后端保留运行。诊断 SSH 已真实认证并执行来宾只读排查；一次 iPad 键盘 Return 已由来宾实际 HID 日志确认送达。随后一次正常密码输入已真实登录 lkx：控制台 UID 501，IOConsoleUsers 的 LoginDone=Yes，Finder 和 Dock 均已启动。正确的控制台会话可读到显示器 1 和实际窗口；此前空显示列表来自查询会话不匹配。上述结果证明来宾已进入用户桌面，但 iPad 可见画面和基础操作仍未验收，黑屏仍属于主线阻塞。CPU、运行库和显示代码在这些诊断中均未改动。随后收起软件键盘的原生 USB 截图已看到真实 macOS Dock 与灰色桌面；但 VMM 在登录后意外退出，App 进入错误状态并保留清理未证明的所有者。因此稳定窗口操作仍未通过，原生系统日志随后确认这次退出为 EXC_BAD_ACCESS / SIGSEGV，访问地址 0xd1；系统因同名崩溃报告数量达到上限未保存调用栈。五份已在宿主备份并固定哈希的旧自有 VMM 报告已移入新的自有归档目录，前次完整日志也已保留。Normal134 stop/post 均为 0；Normal135 使用同一代码和原始配置启动，优先取得登录后的真实窗口操作与必要的崩溃调用栈，不能把暂时可见当作完成。

下列项目可以在基本启动和可用性完成后继续：

| 项目 | 当前范围 | 后续实现 |
| --- | --- | --- |
| GPU 高级调度优化（基本 FIFO 完成链属主线） | Normal122 已取得真实 GPU hang 报告，基本命令完成及跨队列依赖正在主线修复；原 event、值与 commit 保留 | 基本桌面可用后再优化延迟与吞吐；所有完成及 scheduled 通知均需真实原生状态支持 |
| Min/Max 采样器归约 | 旧系统只保留实际原生 WeightedAverage 默认值 0；原生 setter 存在时按真实 ABI 调用，缺失时非零模式明确不支持；基本来宾是否仅需默认值待实测 | 在支持的平台接口或真实等价执行实现完成后开放 Min/Max，不伪造高级能力 |
| HDR、外接显示及扩展色彩管理 | 优先 iPad 自有基本显示路径 | 完成真实显示服务和色彩能力适配 |
| 新版 IOSurfaceAccelerator 转换命令 | 未知接口保持明确不支持 | 根据真实布局、驱动能力实现转换和回退 |
| 音频 | 首次画面配置不创建音频设备 | 接入实际输入、输出和音频会话 |
| VideoToolbox 视频编解码加速 | Runtime72 已安装两入口兼容；Main27 跳过可选 accelerator。缺完整原生 API 时明确返回不支持，不制造 session；来宾响应仍待实际观察 | 在真实可用的 host-session API、回调与生命周期完成后再开放；保留基本图形和显示，不强行覆盖原生不支持谓词 |
| 外部物理 USB 及恢复连接 | AVP 外部连接保持 disconnected；保留虚拟控制器和标准键鼠 | 在真实可用的主机接口上实现连接、断开和恢复 |
| SVE、SME、AMX、嵌套 EL2/VHE | 不宣告未实现的 CPU 特性 | 实现真实执行、异常和完整状态管理后再开放 |
| FEAT_CSV2_2 / SCXTNUM | 已使用创建 CPU 前明确不提供该可选特性的配置；按同 CPU 实际 PFR 决定状态片段是否存在 | 原生状态访问、来宾访问及完整保存恢复均实现后，再宣告此特性；不以 SYS 假成功替代 |
| PMU 性能监控及 PMCR1 | 既有 CPU 配置不提供 PMU；仅在同 CPU 实际 PMUVer 为零且可选状态也为零时，才可省略该状态片段 | 完成真正的寄存器访问、计数、事件及中断消费者后，再提供性能统计；非零状态继续拒绝，不使用未知内核字段或寄存器影子冒充实现 |
| 跨 CPU 配置的快照与迁移 | 不宣称跨特征配置兼容 | 实现状态有效性、配置及代际匹配和完整恢复 |
| AVP 视频端点的快照、归档恢复 | 当前两入口兼容范围仅为新启动、设备 reset 和消息处理；不支持归档恢复。原归档 decoder 的终止消息路径没有安全的空消息回退 | 接入真实终止消息与归档运输，或在原错误返回路径明确拒绝；不伪造消息和恢复成功 |
| CPU 运行期间修改、撤销已有 RAM 映射 | Runtime66 已实现真实 native4/5 区间事务、独立区间账本和读取代次管理；Normal74 未重现此前拒绝，内核二级映射同步路径已有保存代码证据 | 长期动态回收优化可后续实现；不将静态同步路径证据称为每次操作的独立运行验证 |
| 启动日志重定向的可靠性 | Normal75 在 fd2 校验处被拒绝；同一 App79 的 Normal76 再次启动已通过，具体不符谓词尚未确定 | 检查 Main 中未验证的 freopen 返回和标准流描述符状态，保留消费者原校验；基本启动优先 |
| 动态沙箱配置与非必需服务注册 | 保留真实不可用结果及自有进程身份校验 | 在支持的平台接口上接入真实隔离和生命周期 |
| macOS rawHID、媒体键及扩展输入 | 基础 USB 键盘和屏幕坐标鼠标属于当前主线 | 基础输入验证后补齐扩展事件 |

CPU 执行、基本 RAM 映射、GIC/计时器、磁盘启动、基本显示和输入均属于当前主线。首次画面配置暂不创建网卡；来宾基本启动后继续网络及 SSH，最终仍需接入运行包并实际登录。

任何延期项一旦阻挡基本启动，应立即恢复为当前阻塞修复。此前 V5 等文件保留为历史记录，其中旧版本安装、审批和崩溃状态不代表当前设备状态。

此前阻塞的精确来源已保存：Normal81 的 MSI TYPE valid-mask panic 由 Runtime71 的 VMApple bit31 兼容修复；Normal82 的 VT 队列空调用由真实 LR 定位到弱导入 Create；Normal85 日志进一步暴露 PVG 的 depth24 能力查询缺口。旧 UART 只有固件 Stage1/2 文本，不代表未进入内核。Runtime72 的原始 NULL 分支静态检查见 [简短 HOST 证据](../DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/independent27-runtime72-vt-coldboot-null-branches-host-v1-attempt1/proof.json)：Create 失败正常返回，Deliver 保留错误响应，析构和 Invalidate 检查 NULL，归档恢复仍延期。此证据不证明来宾接受不支持响应或已启动。

串口诊断的 serial/debug boot-args 已由 Main32 在 Normal96 启动前精确恢复，实际日志记录 `originalReadbackVerified=1` 与 `resultSaved=1`；原类型、原值及诊断值备份仍保留。Main32 继承 Main30 完整恢复逻辑，并在每次 Run 前恢复原值；没有复制整个 AuxiliaryStorage 或修改其他恢复变量。成功启动的现有 ACK/COMMITTED 协议会保留来宾运行，成功后不执行 stop/post。

Normal135 在同一 Runtime102 / App130 下再次推进到登录后的桌面容器，但 VMM 于 2026-10-18 22:13:20 UTC 发生 SIGSEGV，系统标注可能的指针认证失败；完整调用栈仍因报告数量限制未保存。Normal135 stop/post 均为 0。Runtime103 / App131 只在自有 VMM 的 MD 库增加一次性原始 PC/LR/寄存器记录，保留原默认信号退出，不恢复故障执行；所有 CPU、GPU 及 34 个 App 功能对象保持原样。当前继续定位并修复这次崩溃，稳定可见的窗口和键鼠操作仍是验收条件。


Normal136 在 Runtime103 / App131 中再次出现 VMM 段错误，新增的一次性记录实际取得原始 PC/LR。返回地址准确对应 VMM RVA 0xdea1c，调用点 0xdea18 经真实认证桩 0x411314 / 槽 0x4c6218 / 导入87 调用 CMBlockBufferCreateWithMemoryBlock；PC 为签名空指针。该弱依赖原路径为 macOS 的 CoreMedia.framework/Versions/A/CoreMedia，iPad 原生实际路径不含 Versions/A。已读取当前 iPad 原生 CoreMedia 的完整头部及导出表，三项 CMBlockBuffer 导入均为真实直接导出；Runtime104 仅修正这一条加载路径并保留原弱标志、序号、认证槽、指令与14项权限，App132 仅重连运行库锚点。Normal136 stop/post 均实际为0。Normal137 已实际安装 Runtime104 / App132：三项 CMBlockBuffer 绑定都指向当前 iPad 原生实现，VMM 存活超过此前崩溃点。稳定可见的窗口和基础输入仍未验收。

Normal137 实际正常登录后，来宾 RAM 中已读到 Finder、Dock、WallpaperAgent，iPad 原生 USB 截图也显示了真实壁纸、菜单和 Dock，但顶部彩色噪带和窗口显示仍异常。随后来宾自行重启；CPU 已有的一次性 reset 记录取得真实 panic：25G83 内核在 `MSR S3_4_C15_C1_4, x8`（0xd51cf188）启用 AMX bit63 时发生 Undefined kernel instruction。原 VMM 从 `__get_cpu_capabilities` 取宿主 AMX 版本填入来宾 `amx_version`，与当前实际不支持 AMX 的 CPU 虚拟化接口矛盾。Runtime105 只把该版本生成点 RVA0x32ffe8 的 UBFX 改成与原缺省分支相同的 MOV w2,0，准确宣告不支持，保留全部 CPU/GPU 和其余144个运行库镜像；AMX 数据和算术执行列入后续实现。App133 只重连运行库锚点。Normal137 stop/post 均为0，新版正在安装；尚不能称为可用来宾完成。

Normal138 已实际使用 Runtime105 / App133，正常登录后打开了 Finder 的“最近使用”窗口以及 Terminal；键盘有效，但窗口、图标和顶部仍有严重花屏，尚未达到基本可用验收。此前 AMX panic 未再次出现。来宾侧 SSH 实际认证成功，并通过正常 sudo 启用了原生 sshd，将固定 vsock 辅助程序的 root 所有启动项安装到 `/Library/LaunchDaemons/com.mac.virtual.independent27.owned-ssh-v2.plist`，RunAtLoad/KeepAlive 为真，重启节流30秒。开机自启动效果待下一次来宾启动确认；iPad 本机回环22222已实际连通来宾，仍需 App 启动对应真实 VZ 转发桥。

当前花屏主线：原 GPU Task 多次调用 iPad16 原生 AGXG14GDevice 不提供的 `minLinearTexturePitchAlignmentForDescriptor:mustMatchExactly:`。新增 Metal15 适配只转接原调用点0x57694到原生 `minLinearTextureAlignmentForPixelFormat:`，保留真实返回，并保持 NSUInteger 输出槽不变；不修改 Apple 类、不绕过 Metal 校验。GPU193 / Runtime106 和自动创建 SSH 桥的 Main38 / App135 已完成主机编译签名，Dev125 正在安装。此时仍未取得新版本花屏改善的执行证据。正常关闭来宾时已观察到原始 guestDidStop 回调，Normal138 stop/post 均为0；iPad未重启。

Normal139 已实际启动自动 SSH 桥，并认证到来宾，确认持久启动项随来宾开机运行。Runtime106 的纹理对齐接口已实际调用，但花屏仍在。Normal142 使用 Runtime107 / App138，仅在自有 GPU 子进程开启原生 Metal API 验证，捕获 `setPurgeableState:` 的真实断言：资源仍被命令缓冲区使用时被改为 Volatile。已准备 GPU193 的两条参数指令兼容候选：缓冲区 RVA0xc294、纹理 RVA0x51964 从原生 Volatile(3) 改为 NonVolatile(2)，保留真实原生调用、返回值及正常对象释放；其余 Metal15 代码与193项导入保持原样。候选尚待来宾运行和内存占用验证，不能据此宣称花屏解决。

后续恢复 GPU 易失缓存回收：在真实命令缓冲区及资源生命周期同步完善后，恢复这两处 Volatile 请求；基础可用版本可暂缓此优化并保留资源至正常释放。不得伪造 GPU 完成、修改事件值或关闭 Metal 验证来掩盖断言。还需移除诊断开销，将原生 IOSurface 显示的100毫秒更新间隔缩短到适合实际刷新率的间隔，减少 CPU 整帧复制；最终以 iPad 原生画面、普通窗口操作和实际资源占用验收。

2026-10-20 当前实机基线：Runtime120 / App156 / Normal157 已实际正常登录，原生 USB 截图显示壁纸、菜单栏、Dock 和多个窗口。用户确认“已基本流畅”。App154 的相邻未租用移动合并与60Hz投递消除了已记录的连续鼠标积压：Normal155 的58组匹配记录从约148ms中位返回降至9.489ms，中位接收至真实来宾光标13.6075ms；不是硬件延迟全量测量。GIC7 只索引已启用中断，保留原优先级/路由判定；映射4仅优化本CPU所属线程读取实际共享页到经检查的pthread栈，保留所有写入、版本、外线程和销毁路径。首帧单次观测Normal155约88秒、156约71秒、157约54秒，用户要求恢复十几秒启动，尚未达标。Terminal Dock图标仍空白，双指滚动与三指手势仍未实现，继续主线。

系统手势组件现已部署 `VZKeyboardPassthroughIndependent27_v2.m`，仅原有边缘/多任务手势路径加入独立 App 身份；原键盘策略及前台、运行标记、解锁、启动完成保护保留。仅标准重载了一次 SpringBoard，iPad 未重启。Normal158 后用户报告“好多了”，组件也实际记录了五次多任务手势抑制。此前用 spindump 未列出空闲组件推断未加载的检查不成立，组件文件已恢复为新版，不能再据此触发重载。

2026-10-21 继续主线：App158 / Runtime120 / Normal159 已安装实际运行，并通过原生登录进入桌面；多指表面8接通硬件滚动、按设置的直接双指滚动，以及公开三指手势到来宾 Control-方向键。真实 Magic Keyboard 双指/三指反馈尚待取得，不把公开三指识别器存在视为触控板三指事件已到达。滚动由实际 VZ27 构造器及 sender 处理，保留输入队列和鼠标按钮释放。SSH22222再次实际认证成功。来宾没有修改偏好，临时 VNC 仅正常登录和截图，已准确清理。

壁纸优先故障已经复现：Aerial 扩展首次连接约30秒后错误3，重试连接后还等待约12至27秒才能呈现播放器；本地467MB视频完整，扩展报告使用已有快照并成功保存新快照。冷启动时系统设置也出现图标占位。图标服务 air64_v22 缺少二进制切片错误需要与真实 GUI 加载关联，不能仅凭包含 SSH 后台服务的日志确定因果。受来宾 TCC 保护的壁纸容器只读枚举被拒，未更改 TCC 或清空缓存。实体 Mac 是27.0.1，来宾是26.6.2，不能将两者当作同版本受控对比。

Runtime121 / App159 已在 HOST 构建并签名：GIC8 仅省略正在执行该 CPU Run 循环的所属线程的自唤醒，其他线程及未执行CPU保持原唤醒和错误；Init4 使用相同有限字段集合并启用O2。字段闭包1081476项等价检查与23项所属/外线程唤醒检查通过，两个CPU对象更新，其余27个和所有GPU对象保持。实际启动性能和壁纸超时改善尚未验证。

用户已在 App158 实测确认 Magic Keyboard 双指滑动可用，随后要求新增反向开关。App160 / Runtime121 / Dev146attempt2 已实际安装：设置→触摸新增“反转滚动方向”，默认关闭，使用既有持久设置写入，独立27消费者每个滚动包读取该值并只对两轴各反转一次；速度与实际原生sender保留。中文沿用包内zh_CN/zh_HK/zh_TW代码，英文有对应条目。此次更新12个自有文件（包括四个文本翻译及对应签名），新哈希4项；未运行未安装的App159/Dev146attempt1。三指触控板手势仍待真实反馈；方向切换和重启后持久性还需通过实际UI使用确认。Normal160将验证新CPU优化，壁纸和图标冷启动尚未宣称解决。
