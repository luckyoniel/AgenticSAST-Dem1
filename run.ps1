$ErrorActionPreference = "Stop"

$MAVEN_VERSION = "3.9.14"
$MAVEN_URL = "https://dlcdn.apache.org/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.zip"
$LOCAL_MAVEN_DIR = Join-Path $PWD ".local-maven"
$MAVEN_ZIP = Join-Path $LOCAL_MAVEN_DIR "maven.zip"
$MAVEN_HOME = Join-Path $LOCAL_MAVEN_DIR "apache-maven-$MAVEN_VERSION"
$MAVEN_CMD = Join-Path $MAVEN_HOME "bin\mvn.cmd"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "🚀 正在初始化 CBot 启动环境..." -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# 1. 检查并下载 Maven
if (-Not (Test-Path $MAVEN_CMD)) {
    Write-Host "[*] 未找到本地 Maven，准备从清华镜像源下载 Maven $MAVEN_VERSION..." -ForegroundColor Yellow
    
    if (-Not (Test-Path $LOCAL_MAVEN_DIR)) {
        New-Item -ItemType Directory -Force -Path $LOCAL_MAVEN_DIR | Out-Null
    }

    Write-Host "[*] 正在下载: $MAVEN_URL"
    Invoke-WebRequest -Uri $MAVEN_URL -OutFile $MAVEN_ZIP
    
    Write-Host "[*] 下载完成，正在解压..."
    Expand-Archive -Path $MAVEN_ZIP -DestinationPath $LOCAL_MAVEN_DIR -Force
    
    Write-Host "[*] 解压完成，清理压缩包..."
    Remove-Item -Path $MAVEN_ZIP -Force
    
    Write-Host "[+] 临时 Maven 安装成功: $MAVEN_HOME" -ForegroundColor Green
} else {
    Write-Host "[+] 已检测到本地缓存的 Maven 环境: $MAVEN_HOME" -ForegroundColor Green
}

# 2. 执行 Spring Boot 编译与启动
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "⚙️ 正在编译并启动 Spring Boot 项目，请稍候..." -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# 将临时 Maven 添加到环境变量以供当前进程使用
$env:Path = "$($MAVEN_HOME)\bin;" + $env:Path

# 执行 spring-boot:run
& $MAVEN_CMD clean spring-boot:run
# 保持窗口打开（如果直接双击运行的话）
Write-Host "服务已退出。按任意键关闭..." -ForegroundColor Yellow
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null

