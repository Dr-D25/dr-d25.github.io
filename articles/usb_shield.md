# Защита от подключения неизвестных USB

## usb_shield.ps1
```ps1
param(
    [switch]$On,
    [switch]$Off,
    [switch]$Gen,
    [switch]$Show,
    [switch]$Eject,
    [switch]$Demo,
    [int]$Interval = 2   # интервал проверки в секундах
)

$LogFile = "$PSScriptRoot\usbkill.log"
$AllowListFile = "$PSScriptRoot\usbkill.allow"
$ConfigFile = "$PSScriptRoot\usbkill.conf"
$Command = "shutdown /s /t 0"

if (Test-Path $ConfigFile) {
    $DemoMode = Get-Content $ConfigFile | ConvertFrom-Json
} else {
    $DemoMode = $true
}

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run as Administrator!" -ForegroundColor Red
    exit 1
}

function Save-DemoMode {
    $DemoMode | ConvertTo-Json | Set-Content -Path $ConfigFile
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp $Message"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Get-USBLegacyDevices {
    $result = @()
    $devices = Get-PnpDevice -Class USB | Where-Object { $_.Status -eq 'OK' }
    foreach ($dev in $devices) {
        $wmi = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -eq $dev.DeviceID }
        $obj = [PSCustomObject]@{
            DeviceID   = $dev.DeviceID
            FriendlyName = $dev.FriendlyName
        }
        $result += $obj
    }
    return $result
}

function Save-AllowList {
    $devices = Get-USBLegacyDevices
    $devices | Export-Clixml -Path $AllowListFile
    Write-Log "White list updated: $($devices.Count) devices."
    return $devices
}

function Load-AllowList {
    if (Test-Path $AllowListFile) {
        return Import-Clixml -Path $AllowListFile
    }
    return $null
}

function Show-USB {
    $devices = Get-USBLegacyDevices
    if (-not $devices) {
        Write-Host "No USB devices found." -ForegroundColor Yellow
        return
    }
    $devices | ForEach-Object { 
        Write-Host "DeviceID: $($_.DeviceID)   Name: $($_.FriendlyName)"
    }
}

function Add-ToAllowList {
    $devices = Get-USBLegacyDevices
    if (-not $devices) {
        Write-Host "No USB devices connected." -ForegroundColor Yellow
        return
    }
    Write-Host "List of USB devices:"
    for ($i=0; $i -lt $devices.Count; $i++) {
        Write-Host "$i. $($devices[$i].FriendlyName) ($($devices[$i].DeviceID))"
    }
    $choice = Read-Host "Enter the number of device to add to white list"
    if ($choice -match '^\d+$' -and $choice -lt $devices.Count) {
        $selected = $devices[$choice]
        $current = Load-AllowList
        if (-not $current) { $current = @() }
        if ($current.DeviceID -contains $selected.DeviceID) {
            Write-Host "Device already in white list." -ForegroundColor Yellow
        } else {
            $current += $selected
            $current | Export-Clixml -Path $AllowListFile
            Write-Log "Added device: $($selected.FriendlyName)"
            Write-Host "Device added." -ForegroundColor Green
        }
    } else {
        Write-Host "Invalid number." -ForegroundColor Red
    }
}

function Start-Monitor {
    $allowList = Load-AllowList
    if (-not $allowList) {
        Write-Host "White list is empty. Creating from current USB devices..." -ForegroundColor Yellow
        $allowList = Save-AllowList
    }

    Write-Log "Monitoring started (polling every $Interval seconds). Demo mode: $DemoMode"
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Cyan

    $allowHash = @{}
    foreach ($dev in $allowList) {
        $allowHash[$dev.DeviceID] = $true
    }

    $previousDevices = $allowList

    while ($true) {
        $currentDevices = Get-USBLegacyDevices
        $newDevices = $currentDevices | Where-Object { 
            -not ($previousDevices.DeviceID -contains $_.DeviceID)
        }

        foreach ($dev in $newDevices) {
            Write-Log "New device detected: $($dev.FriendlyName) ($($dev.DeviceID))"
            if (-not $allowHash.ContainsKey($dev.DeviceID)) {
                Write-Log "UNKNOWN DEVICE! $($dev.FriendlyName)"
                if (-not $DemoMode) {
                    Write-Log "Executing command: $Command"
                    Start-Process -FilePath "shutdown" -ArgumentList "/s /t 0" -WindowStyle Hidden
                } else {
                    Write-Log "DEMO MODE: command NOT executed."
                }
                $allowHash[$dev.DeviceID] = $true
            } else {
                Write-Log "Device is in white list, ignored."
            }
        }

        $previousDevices = $currentDevices
        Start-Sleep -Seconds $Interval
    }
}

if ($On) {
    if (Test-Path "$AllowListFile.disabled") {
        Rename-Item -Path "$AllowListFile.disabled" -NewName "usbkill.allow"
        Write-Host "Monitoring enabled." -ForegroundColor Green
    } else {
        Write-Host "Monitoring already active or file missing. Use -Gen to create." -ForegroundColor Yellow
    }
    exit
}

if ($Off) {
    if (Test-Path $AllowListFile) {
        Rename-Item -Path $AllowListFile -NewName "usbkill.allow.disabled"
        Write-Host "Monitoring disabled (file renamed)." -ForegroundColor Yellow
    } else {
        Write-Host "Allow list file not found. Monitoring might be already off." -ForegroundColor Yellow
    }
    exit
}

if ($Gen) {
    Save-AllowList
    Write-Host "White list updated." -ForegroundColor Green
    exit
}

if ($Show) {
    Show-USB
    exit
}

if ($Eject) {
    Add-ToAllowList
    exit
}

if ($Demo) {
    $DemoMode = -not $DemoMode
    Save-DemoMode
    Write-Host "Demo mode is now: $DemoMode" -ForegroundColor Cyan
    Write-Log "Demo mode changed to $DemoMode"
    exit
}

Write-Host "Starting monitoring (polling every $Interval seconds)..." -ForegroundColor Cyan
Start-Monitor
```
# 🛡️ USBShield

> PowerShell-скрипт для Windows, который автоматически **отключает компьютер** (или выполняет другую команду) при подключении **неизвестного USB-устройства**, не внесённого в белый список.  
> Надёжная защита от несанкционированного доступа через USB-порты.

## 🔥 Особенности

- ✅ **Автоматическое создание белого списка** – при первом запуске все подключённые USB‑устройства становятся «доверенными».
- ✅ **Обновление списка на лету** – добавляйте новые устройства через простые команды.
- ✅ **Демо-режим** – безопасное тестирование без реального выключения (включён по умолчанию).
- ✅ **Сохранение состояния** – демо‑режим запоминается между запусками.
- ✅ **Логирование** – все события записываются в файл для аудита.
- ✅ **Работает на Windows 7/8/10/11** – использует встроенные механизмы WMI.

---

## ⚠️ Предупреждение

- Скрипт требует **прав администратора**.
- По умолчанию включён **демо-режим** – только логирование, без выключения.
- Перед отключением демо-режима **убедитесь**, что все ваши постоянные USB‑устройства (клавиатура, мышь, флешки) уже есть в белом списке, иначе они вызовут срабатывание.

---

## 📥 Установка

1. Скачайте файл `USBShield.ps1` (или скопируйте код из репозитория).
2. Поместите его в любую папку (например, `C:\Tools\USBShield\`).
3. Запустите **PowerShell от имени администратора** и разрешите выполнение скриптов (если ещё не сделано):
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

---

## 🚀 Использование
1. Первый запуск (создание белого списка)
```powershell
.\USBShield.ps1
```
Скрипт просканирует текущие USB‑устройства, сохранит их DeviceID в файл USBShield.allow и запустит мониторинг в демо-режиме.

2. Отключение демо‑режима (разрешить выключение)
```powershell
.\USBShield.ps1 -Demo
```
Состояние сохранится в USBShield.conf. Теперь при подключении неизвестного USB компьютер выключится.

3. Обновление белого списка (добавить все текущие USB)
```powershell
.\USBShield.ps1 -Gen
```

4. Показать текущие USB‑устройства
```powershell
.\USBShield.ps1 -Show
```

5. Добавить конкретное устройство в белый список (интерактивно)
```powershell
.\USBShield.ps1 -Eject
```
Вы увидите список устройств с номерами, выберите нужное.

6. Включить / отключить мониторинг (без удаления файлов)
```powershell
.\USBShield.ps1 -On   # включить
.\USBShield.ps1 -Off  # отключить
```
При отключении файл белого списка переименовывается в .disabled.

## 🔧 Настройка

В начале файла USBShield.ps1 можно изменить:

`$Command` – команда при срабатывании (по умолчанию shutdown /s /t 0).

`$LogFile` – путь к лог‑файлу (по умолчанию USBShield.log).

`$AllowListFile` – файл белого списка (USBShield.allow).

`$ConfigFile` – файл состояния демо‑режима (USBShield.conf).

## 🧠 Как это работает
- При старте скрипт получает список всех подключённых USB‑устройств через Get-PnpDevice и сохраняет их DeviceID в белый список (если он ещё не существует).
- Подписывается на системные события Win32_DeviceChangeEvent с типом 2 (добавление устройства).
- При появлении нового USB сравнивает его DeviceID с элементами белого списка.
- Если совпадений нет – выполняет команду из $Command (если демо‑режим выключен).

## 🖥️ Пример лога
```text
2026-07-05 18:27:21 Monitoring started (Win32_DeviceChangeEvent). Demo mode: False
2026-07-05 18:28:05 Device arrival event detected.
2026-07-05 18:28:05 UNKNOWN DEVICE CONNECTED: Kingston DataTraveler (USB\VID_0951&PID_1666\1234567890AB)
2026-07-05 18:28:05 Executing command: shutdown /s /t 0
```


## wipeusb.ps1

```ps1
# wipeusb.ps1 — защита от неизвестных USB
# Режимы: delete (быстрое удаление) или wipe (полное затирание)
# Версия 1.0

param(
    [switch]$On,
    [switch]$Off,
    [switch]$Gen,
    [switch]$Show,
    [switch]$Eject,
    [switch]$Demo
)

$WipeMode = "delete"   # <--- измените на "wipe", если нужно затирание
# ------------------------------

$LogFile = "$PSScriptRoot\USBShield.log"
$AllowListFile = "$PSScriptRoot\USBShield.allow"
$ConfigFile = "$PSScriptRoot\USBShield.conf"

if (Test-Path $ConfigFile) {
    $DemoMode = Get-Content $ConfigFile | ConvertFrom-Json
} else {
    $DemoMode = $true
}

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: Run as Administrator!" -ForegroundColor Red
    exit 1
}

function Save-DemoMode {
    $DemoMode | ConvertTo-Json | Set-Content -Path $ConfigFile
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp $Message"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Get-RemovableDrives {
    Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object {
        [PSCustomObject]@{
            DriveLetter   = $_.DeviceID
            SerialNumber  = $_.VolumeSerialNumber
            Size          = $_.Size
            FreeSpace     = $_.FreeSpace
        }
    }
}

function Save-AllowList {
    $drives = Get-RemovableDrives
    $serials = $drives | ForEach-Object { $_.SerialNumber }
    $serials | Set-Content -Path $AllowListFile
    Write-Log "White list updated: $($serials.Count) serial numbers."
    return $serials
}

function Load-AllowList {
    if (Test-Path $AllowListFile) {
        return Get-Content $AllowListFile
    }
    return @()
}

function Show-USB {
    $drives = Get-RemovableDrives
    if (-not $drives) {
        Write-Host "No removable drives found." -ForegroundColor Yellow
        return
    }
    $drives | ForEach-Object { 
        $sizeGB = if ($_.Size) { [math]::Round($_.Size/1GB,2) } else { "unknown" }
        Write-Host "Drive: $($_.DriveLetter)  Serial: $($_.SerialNumber)  Size: $sizeGB GB"
    }
}

function Add-ToAllowList {
    $drives = Get-RemovableDrives
    if (-not $drives) {
        Write-Host "No removable drives found." -ForegroundColor Yellow
        return
    }
    Write-Host "List of removable drives:"
    for ($i=0; $i -lt $drives.Count; $i++) {
        Write-Host "$i. $($drives[$i].DriveLetter)  Serial: $($drives[$i].SerialNumber)"
    }
    $choice = Read-Host "Enter the number of drive to add to white list"
    if ($choice -match '^\d+$' -and $choice -lt $drives.Count) {
        $serial = $drives[$choice].SerialNumber
        $current = Load-AllowList
        if ($current -contains $serial) {
            Write-Host "Drive already in white list." -ForegroundColor Yellow
        } else {
            $current += $serial
            $current | Set-Content -Path $AllowListFile
            Write-Log "Added drive $($drives[$choice].DriveLetter) with serial $serial"
            Write-Host "Drive added." -ForegroundColor Green
        }
    } else {
        Write-Host "Invalid number." -ForegroundColor Red
    }
}

function Delete-Drive {
    param([string]$DriveLetter)
    
    $DriveLetter = $DriveLetter -replace ':$', ''
    $drivePath = $DriveLetter + ":\"

    if (-not (Test-Path $drivePath)) {
        Write-Log "ERROR: Drive $drivePath not accessible."
        return
    }

    Write-Log "Deleting all files and folders on $drivePath ..."
    try {
        Get-ChildItem -Path $drivePath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "All files and folders deleted from $drivePath"
    } catch {
        Write-Log "ERROR during deletion: $_"
    }
}

function Wipe-Drive {
    param([string]$DriveLetter)
    
    $DriveLetter = $DriveLetter -replace ':$', ''
    $drivePath = $DriveLetter + ":\"

    if (-not (Test-Path $drivePath)) {
        Write-Log "ERROR: Drive $drivePath not accessible."
        return
    }

    Write-Log "Wiping drive $drivePath by writing random data until full..."
    try {
        $chunkSize = 1MB
        $random = New-Object System.Random
        $buffer = New-Object byte[] $chunkSize
        $filePath = Join-Path $drivePath "wipe_temp_$(Get-Random).bin"
        $fileStream = [System.IO.File]::OpenWrite($filePath)
        $totalWritten = 0
        try {
            while ($true) {
                $random.NextBytes($buffer)
                $fileStream.Write($buffer, 0, $buffer.Length)
                $totalWritten += $chunkSize
                if ($totalWritten % (100 * $chunkSize) -eq 0) {
                    Write-Log "Wrote $([math]::Round($totalWritten/1GB,2)) GB to $drivePath"
                }
            }
        } catch [System.IO.IOException] {
            Write-Log "Wipe completed: wrote $([math]::Round($totalWritten/1GB,2)) GB to $drivePath before disk full."
        } finally {
            $fileStream.Close()
            Remove-Item $filePath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "ERROR during wiping: $_"
    }
}

function Start-Monitor {
    $allowList = Load-AllowList
    if (-not $allowList) {
        Write-Host "White list is empty. Creating from current drives..." -ForegroundColor Yellow
        $allowList = Save-AllowList
    }

    Write-Log "Monitoring started (polling). Demo mode: $DemoMode, Mode: $WipeMode"
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Cyan

    $global:previousSerials = Get-RemovableDrives | ForEach-Object { $_.SerialNumber }
    Write-Log "Initial serials: $($global:previousSerials -join ', ')"

    while ($true) {
        Start-Sleep -Seconds 3
        $currentDrives = Get-RemovableDrives
        $currentSerials = $currentDrives | ForEach-Object { $_.SerialNumber }
        $newSerials = $currentSerials | Where-Object { $_ -notin $global:previousSerials }
        if ($newSerials) {
            Write-Log "New drive(s) detected with serial(s): $($newSerials -join ', ')"
            Start-Sleep -Seconds 2
            foreach ($serial in $newSerials) {
                $drive = $currentDrives | Where-Object { $_.SerialNumber -eq $serial }
                if ($drive) {
                    $driveLetter = $drive.DriveLetter
                    if ($allowList -contains $serial) {
                        Write-Log "Drive $driveLetter is in white list, ignoring."
                    } else {
                        Write-Log "UNKNOWN DRIVE! Processing $driveLetter"
                        if (-not $DemoMode) {
                            if ($WipeMode -eq "delete") {
                                Delete-Drive -DriveLetter $driveLetter
                            } else {
                                Wipe-Drive -DriveLetter $driveLetter
                            }
                        } else {
                            Write-Log "DEMO MODE: $WipeMode would be performed on $driveLetter"
                        }
                        $allowList += $serial
                        $allowList | Set-Content -Path $AllowListFile
                    }
                }
            }
        }
        $global:previousSerials = $currentSerials
    }
}

if ($On) {
    if (Test-Path "$AllowListFile.disabled") {
        Rename-Item -Path "$AllowListFile.disabled" -NewName "USBShield.allow"
        Write-Host "Monitoring enabled." -ForegroundColor Green
    } else {
        Write-Host "Monitoring already active or file missing. Use -Gen to create." -ForegroundColor Yellow
    }
    exit
}

if ($Off) {
    if (Test-Path $AllowListFile) {
        Rename-Item -Path $AllowListFile -NewName "USBShield.allow.disabled"
        Write-Host "Monitoring disabled (file renamed)." -ForegroundColor Yellow
    } else {
        Write-Host "Allow list file not found. Monitoring might be already off." -ForegroundColor Yellow
    }
    exit
}

if ($Gen) {
    Save-AllowList
    Write-Host "White list updated." -ForegroundColor Green
    exit
}

if ($Show) {
    Show-USB
    exit
}

if ($Eject) {
    Add-ToAllowList
    exit
}

if ($Demo) {
    $DemoMode = -not $DemoMode
    Save-DemoMode
    Write-Host "Demo mode is now: $DemoMode" -ForegroundColor Cyan
    Write-Log "Demo mode changed to $DemoMode"
    exit
}

Write-Host "Starting monitoring (polling)..." -ForegroundColor Cyan
Start-Monitor
```

---

# 🛡️ wipeusb

> PowerShell-скрипт для защиты компьютера от несанкционированного использования USB-накопителей.  
> При подключении **неизвестной** флешки (не внесённой в белый список) скрипт автоматически **удаляет все файлы** или **полностью затирает** её случайными данными.

---

## 🔥 Особенности

- ✅ **Автоматическое создание белого списка** – при первом запуске все подключённые съёмные диски становятся доверенными.
- ✅ **Два режима работы**:
  - `delete` – быстрое удаление всех файлов и папок (восстановление возможно).
  - `wipe` – полное затирание случайными данными до заполнения диска (необратимо).
- ✅ **Демо-режим** – безопасное тестирование без реальных действий (включён по умолчанию).
- ✅ **Сохранение состояния** – демо‑режим запоминается между запусками.
- ✅ **Логирование** – все события записываются в файл.
- ✅ **Работает на любых съёмных дисках** (флешки, кард-ридеры, внешние HDD).
- ✅ **Не требует сложной настройки** – запустил и забыл.

---

## ⚠️ Предупреждение

- Скрипт требует **прав администратора**.
- Режим `wipe` **необратим** – данные восстановить невозможно.
- Режим `delete` **не гарантирует** безвозвратное удаление – файлы можно восстановить программами-реаниматорами.
- **По умолчанию включён демо-режим** – только логирование. Перед включением боевого режима убедитесь, что все ваши постоянные флешки уже в белом списке.

---

## 📥 Установка

1. Скачайте файл `wipeusb.ps1` (или скопируйте код).
2. Поместите его в удобную папку (например, `C:\Tools\wipeusb\`).
3. Запустите **PowerShell от имени администратора** и разрешите выполнение скриптов (если ещё не сделано):
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser wipeusb

> PowerShell-скрипт для защиты компьютера от несанкционированного использования USB-накопителей.  
> При подключении **неизвестной** флешки (не внесённой в белый список) скрипт автоматически **удаляет все файлы** или **полностью затирает** её случайными данными.

---

## 🔥 Особенности

- ✅ **Автоматическое создание белого списка** – при первом запуске все подключённые съёмные диски становятся доверенными.
- ✅ **Два режима работы**:
  - `delete` – быстрое удаление всех файлов и папок (восстановление возможно).
  - `wipe` – полное затирание случайными данными до заполнения диска (необратимо).
- ✅ **Демо-режим** – безопасное тестирование без реальных действий (включён по умолчанию).
- ✅ **Сохранение состояния** – демо‑режим запоминается между запусками.
- ✅ **Логирование** – все события записываются в файл.
- ✅ **Работает на любых съёмных дисках** (флешки, кард-ридеры, внешние HDD).
- ✅ **Не требует сложной настройки** – запустил и забыл.

---

## ⚠️ Предупреждение

- Скрипт требует **прав администратора**.
- Режим `wipe` **необратим** – данные восстановить невозможно.
- Режим `delete` **не гарантирует** безвозвратное удаление – файлы можно восстановить программами-реаниматорами.
- **По умолчанию включён демо-режим** – только логирование. Перед включением боевого режима убедитесь, что все ваши постоянные флешки уже в белом списке.

---

## 📥 Установка

1. Скачайте файл `wipeusb.ps1` (или скопируйте код).
2. Поместите его в удобную папку (например, `C:\Tools\wipeusb\`).
3. Запустите **PowerShell от имени администратора** и разрешите выполнение скриптов (если ещё не сделано):
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
