# AikenVPN — сборка единого EXE без внешних зависимостей
# Использование:
#   .\build.ps1              # без OpenVPN (OpenVPN ищется в системе как fallback)
#   .\build.ps1 -WithOpenVPN # с встроенным openvpn.exe (требует assets/openvpn/)

param(
    [switch]$WithOpenVPN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Проверка зависимостей сборки ──────────────────────────────────────────────
if (-not (Get-Command wails -ErrorAction SilentlyContinue)) {
    Write-Error "wails не найден. Установите: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
}

# ── Опциональная встройка OpenVPN ─────────────────────────────────────────────
$tags = ""
if ($WithOpenVPN) {
    $ovpnDir = Join-Path $PSScriptRoot "internal\vpn\assets\openvpn"
    $requiredFiles = @("openvpn.exe", "libssl-3-x64.dll", "libcrypto-3-x64.dll", "liblzo2-2.dll")

    foreach ($f in $requiredFiles) {
        if (-not (Test-Path (Join-Path $ovpnDir $f))) {
            Write-Error @"
Файл не найден: $ovpnDir\$f

Распакуйте OpenVPN вручную:
  1. Скачайте: https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.12-I003-amd64.msi
  2. msiexec /a openvpn.msi /qn TARGETDIR=C:\ovpn_extract
  3. Скопируйте из C:\ovpn_extract\OpenVPN\bin\ в ${ovpnDir}:
       openvpn.exe, libssl-3-x64.dll, libcrypto-3-x64.dll, liblzo2-2.dll
"@
        }
    }

    $tags = "with_openvpn"
    Write-Host "OpenVPN: встроен из $ovpnDir" -ForegroundColor Green

    $totalMB = ($requiredFiles | ForEach-Object { (Get-Item (Join-Path $ovpnDir $_)).Length } | Measure-Object -Sum).Sum / 1MB
    Write-Host "  Размер OpenVPN-файлов: $([math]::Round($totalMB, 1)) МБ" -ForegroundColor Gray
} else {
    Write-Host "OpenVPN: не встроен (fallback на системный openvpn.exe)" -ForegroundColor Yellow
}

# ── Wails сборка ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Сборка AikenVPN.exe..." -ForegroundColor Cyan

$wailsArgs = @("build", "-clean", "-platform", "windows/amd64")
if ($tags) {
    $wailsArgs += @("-tags", $tags)
}

& wails @wailsArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Сборка завершилась с ошибкой (код $LASTEXITCODE)"
}

# ── Результат ─────────────────────────────────────────────────────────────────
$exePath = Join-Path $PSScriptRoot "build\bin\AikenVPN.exe"
if (Test-Path $exePath) {
    $sizeMB = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-Host ""
    Write-Host "✓ Готово: $exePath" -ForegroundColor Green
    Write-Host "  Размер: $sizeMB МБ" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Внешние зависимости для пользователя:" -ForegroundColor Cyan
    Write-Host "  WireGuard  — нет (wintun.dll встроен)" -ForegroundColor Green
    Write-Host "  VMess/VLESS/Trojan/SS — нет (xray-core встроен)" -ForegroundColor Green
    if ($WithOpenVPN) {
        Write-Host "  OpenVPN    — нет (встроен)" -ForegroundColor Green
    } else {
        Write-Host "  OpenVPN    — опционально (системный fallback)" -ForegroundColor Yellow
    }
    Write-Host "  L2TP/IKEv2/SSTP/PPTP — Windows built-in (rasdial)" -ForegroundColor Gray
} else {
    Write-Warning "Файл $exePath не найден — проверьте вывод wails выше"
}
