@echo off
echo Windows权限维持工具 - 构建脚本
echo =================================

echo 正在检查Go环境...
go version
if %errorlevel% neq 0 (
    echo 错误: 未找到Go环境，请先安装Go
    pause
    exit /b 1
)

echo.
echo 正在下载依赖...
go mod tidy
if %errorlevel% neq 0 (
    echo 错误: 依赖下载失败
    pause
    exit /b 1
)

echo.
echo 正在编译程序...
go build -ldflags="-s -w" -o windows-persistence.exe
if %errorlevel% neq 0 (
    echo 错误: 编译失败
    pause
    exit /b 1
)

echo.
echo 编译成功！
echo 生成的文件: windows-persistence.exe
echo.
echo 使用方法:
echo 1. 以管理员身份运行命令提示符
echo 2. 切换到程序所在目录
echo 3. 运行: windows-persistence.exe
echo.
echo 注意: 部分功能需要管理员权限
echo.

pause
