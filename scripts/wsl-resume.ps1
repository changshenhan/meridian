# WSL 恢复脚本(重启后执行,幂等)——2026-08-17
# 用途: 重启落地 VirtualMachinePlatform 后,把 Ubuntu 导入 D:\WSL 并引导 ZK 工具链
# 前置: 已装 WSL 引擎 2.7.11(winget)+ VirtualMachinePlatform 已 staged
$ErrorActionPreference = 'Stop'
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$DIST = 'MeridianUbuntu'
$VHD_DIR = 'D:\WSL\ubuntu'
$ROOTFS = 'D:\WSL\downloads\ubuntu-noble.rootfs.tar.gz'
$REPO = 'C:\Users\18299\Desktop\Meridian\meridian'

Write-Output "=== [0] 校验 VirtualMachinePlatform 已落地 ==="
$vmc = Get-Service -Name vmcompute -ErrorAction SilentlyContinue
if (-not $vmc) {
    Write-Output "FATAL: vmcompute 服务不存在 —— 重启未生效或功能未启用。请确认已重启。"
    exit 1
}
Write-Output "vmcompute 服务存在 (Status=$($vmc.Status))"

Write-Output "=== [1] 导入 Ubuntu 到 D:\WSL\ubuntu(幂等) ==="
$existing = wsl --list --quiet 2>$null | Where-Object { $_.Trim() -eq $DIST }
if (-not $existing) {
    wsl --import $DIST $VHD_DIR $ROOTFS --version 2
    Write-Output "已导入 $DIST"
} else {
    Write-Output "$DIST 已存在,跳过导入"
}

Write-Output "=== [2] 验证发行版 ==="
wsl --list --verbose

Write-Output "=== [3] 启动引导脚本(装 nargo + bb) ==="
$wslScript = ($REPO -replace '\\', '/') + '/scripts/wsl-bootstrap.sh'
$mntPath = 'mnt/c/' + ($REPO -replace '^C:\\', '' -replace '\\', '/')
$bootstrap = "/$mntPath/scripts/wsl-bootstrap.sh"
Write-Output "WSL 内路径: $bootstrap"
wsl -d $DIST -u root bash -c "bash $bootstrap 2>&1"

Write-Output "=== 完成 ==="
