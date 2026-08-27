# ============================================================
# Restore-NetworkDefaults.ps1
# Возвращает все изменённые параметры к дефолтным:
# - Включает Interrupt Moderation, Flow Control, LSO, Checksum Offload
# - Устанавливает буферы в 512 (типичный дефолт)
# - Удаляет NetworkThrottlingIndex (или ставит 0x0A)
# - Включает реальный мониторинг Defender
# ============================================================

# Проверка прав
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Запустите PowerShell от имени Администратора!" -ForegroundColor Red
    exit 1
}

# ---------- 1. Восстановление NetworkThrottlingIndex ----------
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
if (Test-Path $regPath) {
    # Удаляем параметр, чтобы система использовала значение по умолчанию (10)
    Remove-ItemProperty -Path $regPath -Name "NetworkThrottlingIndex" -ErrorAction SilentlyContinue
    Write-Host "[OK] NetworkThrottlingIndex удалён (дефолт: 10)" -ForegroundColor Green
} else {
    Write-Host "[!] Путь реестра не найден, пропускаем" -ForegroundColor Yellow
}

# ---------- 2. Включение реального мониторинга Defender ----------
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "[OK] Реальный мониторинг Defender включён" -ForegroundColor Green
} catch {
    Write-Host "[!] Не удалось включить Defender (возможно, другой антивирус)" -ForegroundColor Yellow
}

# ---------- 3. Получение физических адаптеров ----------
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.Name -notmatch 'Virtual|VPN|Loopback|Bluetooth' }
if (-not $adapters) {
    Write-Host "Не найдено активных физических адаптеров!" -ForegroundColor Red
    exit 1
}

foreach ($adapter in $adapters) {
    Write-Host "`nВосстановление адаптера: $($adapter.Name)" -ForegroundColor Cyan
    $props = Get-NetAdapterAdvancedProperty -Name $adapter.Name

    # RSS – оставляем как есть (обычно включён по умолчанию), но можно не трогать
    # Если хотите явно включить RSS – раскомментируйте:
    # $rss = $props | Where-Object { $_.DisplayName -like "*RSS*" -and $_.DisplayName -notlike "*Queue*" }
    # if ($rss) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $rss.DisplayName -DisplayValue "1" -ErrorAction SilentlyContinue }

    # Interrupt Moderation – включаем (1)
    $intMod = $props | Where-Object { $_.DisplayName -like "*InterruptModeration*" }
    if ($intMod) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $intMod.DisplayName -DisplayValue "1" -ErrorAction SilentlyContinue
        Write-Host "  [+] Interrupt Moderation включён" -ForegroundColor Gray }
    else { Write-Host "  [!] InterruptModeration не найден" -ForegroundColor Yellow }

    # Flow Control – включаем (1)
    $flow = $props | Where-Object { $_.DisplayName -like "*FlowControl*" }
    if ($flow) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $flow.DisplayName -DisplayValue "1" -ErrorAction SilentlyContinue
        Write-Host "  [+] Flow Control включён" -ForegroundColor Gray }
    else { Write-Host "  [!] FlowControl не найден" -ForegroundColor Yellow }

    # Large Send Offload – включаем (1)
    $lso = $props | Where-Object { $_.DisplayName -like "*LSO*" -or $_.DisplayName -like "*LargeSendOffload*" }
    if ($lso) { foreach ($p in $lso) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $p.DisplayName -DisplayValue "1" -ErrorAction SilentlyContinue
            Write-Host "  [+] $($p.DisplayName) включён" -ForegroundColor Gray } }
    else { Write-Host "  [!] LSO не найден" -ForegroundColor Yellow }

    # Checksum Offload – включаем (1)
    $chk = $props | Where-Object { $_.DisplayName -like "*Checksum*Offload*" -or $_.DisplayName -like "*TCPChecksum*" -or $_.DisplayName -like "*UDPChecksum*" }
    if ($chk) { foreach ($p in $chk) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $p.DisplayName -DisplayValue "1" -ErrorAction SilentlyContinue
            Write-Host "  [+] $($p.DisplayName) включён" -ForegroundColor Gray } }
    else { Write-Host "  [!] Checksum Offload не найден" -ForegroundColor Yellow }

    # Буферы – возвращаем к типичному дефолту (512)
    $recv = $props | Where-Object { $_.DisplayName -like "*ReceiveBuffers*" }
    if ($recv) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $recv.DisplayName -DisplayValue "512" -ErrorAction SilentlyContinue
        Write-Host "  [+] Receive Buffers = 512 (дефолт)" -ForegroundColor Gray }
    else { Write-Host "  [!] ReceiveBuffers не найден" -ForegroundColor Yellow }

    $trans = $props | Where-Object { $_.DisplayName -like "*TransmitBuffers*" }
    if ($trans) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $trans.DisplayName -DisplayValue "512" -ErrorAction SilentlyContinue
        Write-Host "  [+] Transmit Buffers = 512 (дефолт)" -ForegroundColor Gray }
    else { Write-Host "  [!] TransmitBuffers не найден" -ForegroundColor Yellow }
}

Write-Host "`n=== Восстановление завершено. Рекомендуется перезагрузка. ===" -ForegroundColor Green