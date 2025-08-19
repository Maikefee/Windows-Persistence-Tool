# Windows权限维持工具 - Go语言版本

这是一个用Go语言编写的Windows权限维持工具，实现了多种常见的权限维持技术。

## 功能特性

### 基础权限维持技术

1. **IFEO镜像劫持** - 通过修改注册表实现程序劫持
2. **启动项后门** - 将程序复制到启动目录实现自启动
3. **注册表启动项后门** - 通过注册表设置启动项
4. **计划任务后门** - 创建定时执行的任务
5. **Winlogon后门** - 修改用户登录初始化程序
6. **Logon Scripts后门** - 设置登录脚本
7. **文件关联后门** - 修改文件关联执行恶意程序
8. **屏幕保护程序后门** - 修改屏幕保护程序
9. **创建影子用户** - 创建隐藏的管理员用户

### 高级权限维持技术

1. **WMI无文件后门** - 使用WMI事件过滤器实现无文件持久化
2. **进程注入** - 向目标进程注入shellcode
3. **DLL劫持检测** - 检测潜在的DLL劫持机会
4. **创建恶意DLL** - 生成用于DLL劫持的恶意DLL
5. **Bitsadmin后门** - 使用Windows BITS服务实现持久化
6. **服务后门** - 创建Windows服务实现持久化
7. **进程管理** - 查看和管理系统进程

## 安装和编译

### 环境要求

- Go 1.21 或更高版本
- Windows操作系统
- 管理员权限（部分功能需要）

### 编译步骤

1. 克隆或下载项目
2. 进入项目目录
3. 运行以下命令编译：

```bash
go mod tidy
go build -o windows-persistence.exe
```

## 使用方法

### 运行程序

```bash
./windows-persistence.exe
```

### 主菜单选项

程序启动后会显示主菜单，包含以下选项：

```
=== Windows权限维持工具 ===
1. IFEO镜像劫持
2. 启动项后门
3. 注册表启动项后门
4. 计划任务后门
5. Winlogon后门
6. Logon Scripts后门
7. 文件关联后门
8. 屏幕保护程序后门
9. 创建影子用户
10. 高级功能
0. 退出
```

### 高级功能菜单

选择"10. 高级功能"后，会显示高级功能菜单：

```
=== 高级权限维持功能 ===
1. WMI无文件后门
2. 进程注入
3. DLL劫持检测
4. 创建恶意DLL
5. Bitsadmin后门
6. 服务后门
7. 删除服务
8. 进程列表
9. 查找进程
0. 返回主菜单
```

## 技术详解

### 1. IFEO镜像劫持

IFEO (Image File Execution Options) 是Windows的一个调试机制，可以用来劫持程序执行。

**原理**: 当系统启动某个程序时，会检查注册表中的IFEO设置，如果存在对应的调试器设置，则会先启动调试器。

**注册表位置**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\[程序名]`

**示例**: 劫持notepad.exe，使其启动时先执行cmd.exe

### 2. 启动项后门

将恶意程序复制到Windows启动目录，实现系统启动时自动执行。

**启动目录位置**:
- 当前用户: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- 所有用户: `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp`

### 3. 注册表启动项

通过修改注册表实现程序自启动。

**常用注册表位置**:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`

### 4. 计划任务后门

使用Windows计划任务服务创建定时执行的任务。

**命令示例**:
```cmd
schtasks /create /sc minute /mo 5 /tn "backdoor" /tr "C:\malware.exe" /f
```

### 5. Winlogon后门

修改用户登录初始化程序，在用户登录时执行恶意代码。

**注册表位置**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

**Userinit值**: 系统会在用户登录时执行此值指定的程序

### 6. WMI无文件后门

使用Windows Management Instrumentation (WMI) 创建事件过滤器，实现无文件持久化。

**原理**: 创建WMI事件过滤器和消费者，当特定事件发生时自动执行恶意程序。

**优势**: 无文件、无进程，难以检测

### 7. 进程注入

向目标进程注入shellcode，实现代码执行。

**常用注入技术**:
- VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
- SetWindowsHookEx
- QueueUserAPC

### 8. DLL劫持

利用Windows DLL搜索顺序，将恶意DLL放在优先位置，实现劫持。

**DLL搜索顺序**:
1. 程序所在目录
2. 当前工作目录
3. 系统目录 (System32)
4. 16位系统目录 (System)
5. Windows目录
6. PATH环境变量

## 安全注意事项

⚠️ **重要警告**: 此工具仅用于教育和研究目的，请勿用于非法活动。

1. **合法使用**: 仅在授权的测试环境中使用
2. **权限要求**: 部分功能需要管理员权限
3. **杀毒软件**: 某些功能可能被杀毒软件检测
4. **系统影响**: 不当使用可能影响系统稳定性

## 检测和防御

### 检测方法

1. **注册表监控**: 监控关键注册表项的修改
2. **文件监控**: 监控启动目录和系统目录的文件变化
3. **进程监控**: 监控异常进程的创建和注入
4. **网络监控**: 监控异常的网络连接
5. **WMI监控**: 监控WMI事件过滤器的创建

### 防御措施

1. **最小权限原则**: 限制用户权限
2. **应用程序白名单**: 只允许运行受信任的程序
3. **注册表保护**: 保护关键注册表项
4. **实时监控**: 部署EDR/EPP解决方案
5. **定期审计**: 定期检查系统安全状态

## 免责声明

本工具仅供安全研究和教育目的使用。使用者需要确保：

1. 在合法授权的环境中使用
2. 遵守当地法律法规
3. 不用于恶意攻击或非法活动
4. 对使用后果承担全部责任

作者不对任何滥用行为承担责任。

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 贡献

欢迎提交Issue和Pull Request来改进这个工具。

## 联系方式

如有问题或建议，请通过GitHub Issues联系。
