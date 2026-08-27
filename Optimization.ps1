# ============================================================
# Optimize-NetworkPPS.ps1
# Включает RSS с числом очередей = числу логических ядер (макс. 16),
# отключает Interrupt Moderation, Flow Control, LSO, Checksum Offload,
# ставит макс. буферы, отключает NetworkThrottlingIndex и Defender.
# ============================================================

# Проверка прав
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Запустите PowerShell от имени Администратора!" -ForegroundColor Red
    exit 1
}

# ---------- 1. Отключение NetworkThrottlingIndex ----------
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord -Force
Write-Host "[OK] NetworkThrottlingIndex = 0xFFFFFFFF" -ForegroundColor Green

# ---------- 2. Отключение реального мониторинга Defender ----------
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-Host "[OK] Реальный мониторинг Defender отключён" -ForegroundColor Green
} catch {
    Write-Host "[!] Не удалось отключить Defender (возможно, другой антивирус)" -ForegroundColor Yellow
}

# ---------- 3. Определение числа логических ядер для RSS ----------
$cpuCount = (Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors
if ($cpuCount -gt 16) { $cpuCount = 16 }   # большинство драйверов не поддерживает >16
Write-Host "Число очередей RSS будет установлено в $cpuCount (логических ядер, лимит 16)" -ForegroundColor Cyan

# ---------- 4. Получение физических адаптеров ----------
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.Name -notmatch 'Virtual|VPN|Loopback|Bluetooth' }
if (-not $adapters) {
    Write-Host "Не найдено активных физических адаптеров!" -ForegroundColor Red
    exit 1
}

foreach ($adapter in $adapters) {
    Write-Host "`nОбработка адаптера: $($adapter.Name)" -ForegroundColor Cyan
    $props = Get-NetAdapterAdvancedProperty -Name $adapter.Name

    # RSS
    $rss = $props | Where-Object { $_.DisplayName -like "*RSS*" -and $_.DisplayName -notlike "*Queue*" -and $_.DisplayName -notlike "*Profile*" }
    if ($rss) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $rss.DisplayName -DisplayValue "1" -ErrorAction SilentlyContinue
        Write-Host "  [+] RSS включён" -ForegroundColor Gray }
    else { Write-Host "  [!] RSS не найден" -ForegroundColor Yellow }

    $queues = $props | Where-Object { $_.DisplayName -like "*NumRSSQueues*" -or $_.DisplayName -like "*RSS Queue*" }
    if ($queues) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $queues.DisplayName -DisplayValue $cpuCount.ToString() -ErrorAction SilentlyContinue
        Write-Host "  [+] RSS очередей = $cpuCount" -ForegroundColor Gray }
    else { Write-Host "  [!] Параметр очередей не найден" -ForegroundColor Yellow }

    # Interrupt Moderation
    $intMod = $props | Where-Object { $_.DisplayName -like "*InterruptModeration*" }
    if ($intMod) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $intMod.DisplayName -DisplayValue "0" -ErrorAction SilentlyContinue
        Write-Host "  [+] Interrupt Moderation отключён" -ForegroundColor Gray }
    else { Write-Host "  [!] InterruptModeration не найден" -ForegroundColor Yellow }

    # Flow Control
    $flow = $props | Where-Object { $_.DisplayName -like "*FlowControl*" }
    if ($flow) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $flow.DisplayName -DisplayValue "0" -ErrorAction SilentlyContinue
        Write-Host "  [+] Flow Control отключён" -ForegroundColor Gray }
    else { Write-Host "  [!] FlowControl не найден" -ForegroundColor Yellow }

    # Large Send Offload (все варианты)
    $lso = $props | Where-Object { $_.DisplayName -like "*LSO*" -or $_.DisplayName -like "*LargeSendOffload*" }
    if ($lso) { foreach ($p in $lso) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $p.DisplayName -DisplayValue "0" -ErrorAction SilentlyContinue
            Write-Host "  [+] $($p.DisplayName) отключён" -ForegroundColor Gray } }
    else { Write-Host "  [!] LSO не найден" -ForegroundColor Yellow }

    # Checksum Offload (все виды)
    $chk = $props | Where-Object { $_.DisplayName -like "*Checksum*Offload*" -or $_.DisplayName -like "*TCPChecksum*" -or $_.DisplayName -like "*UDPChecksum*" }
    if ($chk) { foreach ($p in $chk) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $p.DisplayName -DisplayValue "0" -ErrorAction SilentlyContinue
            Write-Host "  [+] $($p.DisplayName) отключён" -ForegroundColor Gray } }
    else { Write-Host "  [!] Checksum Offload не найден" -ForegroundColor Yellow }

    # Буферы (максимальные – 2048)
    $recv = $props | Where-Object { $_.DisplayName -like "*ReceiveBuffers*" }
    if ($recv) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $recv.DisplayName -DisplayValue "2048" -ErrorAction SilentlyContinue
        Write-Host "  [+] Receive Buffers = 2048" -ForegroundColor Gray }
    else { Write-Host "  [!] ReceiveBuffers не найден" -ForegroundColor Yellow }

    $trans = $props | Where-Object { $_.DisplayName -like "*TransmitBuffers*" }
    if ($trans) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $trans.DisplayName -DisplayValue "2048" -ErrorAction SilentlyContinue
        Write-Host "  [+] Transmit Buffers = 2048" -ForegroundColor Gray }
    else { Write-Host "  [!] TransmitBuffers не найден" -ForegroundColor Yellow }
}

Write-Host "`n=== Оптимизация завершена. Рекомендуется перезагрузка. ===" -ForegroundColor Green