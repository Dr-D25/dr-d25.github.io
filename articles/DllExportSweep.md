# DllExportSweep.ps1

Перечисляет экспорты PE-файла (EXE/DLL) и **при желании вызывает каждый из них через
`rundll32.exe`**, чтобы посмотреть, как DLL ведёт себя на ординал-онли и именованные
экспорты. Полезно для реверса, проверки совместимости, поиска «интересных» функций.

```ps1
#Requires -Version 5.1
<#
.SYNOPSIS
    Перебирает экспорты DLL и (опционально) вызывает каждый ординал через rundll32.

.DESCRIPTION
    ⚠️  ВНИМАНИЕ: с ключом -Dangerous скрипт ИСПОЛНЯЕТ код из DLL через rundll32.exe.
    Запускайте только для собственных/тестовых DLL в изолированной среде (VM, sandbox).
    Без -Dangerous или с -NoCall скрипт только читает таблицу экспортов.

.PARAMETER DllPath
    Путь к анализируемой DLL.

.PARAMETER Dangerous
    Подтверждает, что вы понимаете риск исполнения кода из DLL.

.PARAMETER NoCall
    Только вывести список экспортов, ничего не запускать.

.PARAMETER TimeoutSeconds
    Таймаут на один rundll32 (по умолчанию 10 с).

.PARAMETER DelayMs
    Пауза между вызовами rundll32 (по умолчанию 200 мс).

.PARAMETER Ordinals
    Ограничить перебор указанными ординалами.

.PARAMETER Names
    Ограничить перебор указанными именами экспортов.

.PARAMETER OnlyNamed
    Пропустить ординалы без имён.

.PARAMETER SkipForwarders
    Пропустить forwarder-экспорты.

.PARAMETER SkipEmpty
    Пропустить «пустые» ординалы (AddressOfFunctions == 0).

.PARAMETER ThrottleLimit
    Кол-во одновременных rundll32 (только PowerShell 7+). По умолчанию 1.

.PARAMETER OutCsv
    Сохранить результат в CSV.

.PARAMETER OutJson
    Сохранить результат в JSON.

.PARAMETER LogPath
    Путь к лог-файлу (по умолчанию <script dir>/DllExportRun_<timestamp>.log).

.EXAMPLE
    .\DllExportSweep.ps1 -DllPath .\target.dll -NoCall

.EXAMPLE
    .\DllExportSweep.ps1 -DllPath .\test.dll -Dangerous -TimeoutSeconds 3 -OutCsv .\res.csv
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$DllPath,

    [switch]$Dangerous,
    [switch]$NoCall,

    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 10,

    [ValidateRange(0, 60000)]
    [int]$DelayMs = 200,

    [int[]]$Ordinals,
    [string[]]$Names,
    [switch]$OnlyNamed,
    [switch]$SkipForwarders,
    [switch]$SkipEmpty,

    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 1,

    [string]$OutCsv,
    [string]$OutJson,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $LogPath) {
    $LogPath = Join-Path $scriptDir ("DllExportRun_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".log")
}

function Write-Log([string]$Text, [string]$Color = 'Gray') {
    Write-Host $Text -ForegroundColor $Color
    Add-Content -LiteralPath $LogPath -Value $Text -Encoding UTF8
}

# ---------- Парсер PE ----------
$csharpCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class DllExportReaderV4
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER {
        public ushort e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc,
                      e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=4)] public ushort[] e_res;
        public ushort e_oemid, e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=10)] public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER {
        public ushort Machine, NumberOfSections;
        public uint TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
        public ushort SizeOfOptionalHeader, Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY {
        public uint Characteristics, TimeDateStamp;
        public ushort MajorVersion, MinorVersion;
        public uint Name, Base, NumberOfFunctions, NumberOfNames,
                    AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
    }

    public class ExportInfo {
        public uint Ordinal;
        public string Name;
        public string[] Names = new string[0];
        public bool IsForwarder;
        public string ForwarderTarget;
        public bool IsEmpty;
    }

    public static ExportInfo[] GetExports(string filePath)
    {
        byte[] data = File.ReadAllBytes(filePath);
        if (data.Length < 64) throw new Exception("File too small to be a PE");

        GCHandle h = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            IntPtr basePtr = h.AddrOfPinnedObject();
            IMAGE_DOS_HEADER dos = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(basePtr, typeof(IMAGE_DOS_HEADER));
            if (dos.e_magic != 0x5A4D) throw new Exception("Not a valid PE (MZ missing).");

            long ntOff = dos.e_lfanew;
            if (ntOff < 0 || ntOff + 24 > data.Length) throw new Exception("e_lfanew out of range");
            if (Marshal.ReadInt32((IntPtr)((long)basePtr + ntOff)) != 0x4550)
                throw new Exception("Not a valid PE (PE signature missing).");

            IMAGE_FILE_HEADER fh = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(
                (IntPtr)((long)basePtr + ntOff + 4), typeof(IMAGE_FILE_HEADER));

            long optOff = ntOff + 4 + 20;
            ushort magic = (ushort)Marshal.ReadInt16((IntPtr)((long)basePtr + optOff));

            long expDirOff;
            if (magic == 0x10B) expDirOff = optOff + 0x60;
            else if (magic == 0x20B) expDirOff = optOff + 0x70;
            else throw new Exception("Unknown PE magic: 0x" + magic.ToString("X"));

            uint expRva  = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + expDirOff));
            uint expSize = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + expDirOff + 4));
            if (expRva == 0 || expSize == 0) return new ExportInfo[0];

            long secOff = optOff + fh.SizeOfOptionalHeader;
            var va   = new uint[fh.NumberOfSections];
            var raw  = new uint[fh.NumberOfSections];
            var size = new uint[fh.NumberOfSections];

            for (int i = 0; i < fh.NumberOfSections; i++)
            {
                long so = secOff + i * 40;
                if (so + 40 > data.Length) throw new Exception("Section header out of range");
                uint virtSize = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + so + 8));
                va[i]   = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + so + 12));
                uint rawSize = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + so + 16));
                raw[i]  = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + so + 20));
                size[i] = Math.Max(virtSize, rawSize);
            }

            Func<uint, uint> rva2off = rva => {
                for (int i = 0; i < va.Length; i++)
                    if (rva >= va[i] && rva < va[i] + size[i])
                        return rva - va[i] + raw[i];
                throw new Exception("RVA 0x" + rva.ToString("X") + " not in any section");
            };

            uint expOff = rva2off(expRva);
            if (expOff + 40 > data.Length) throw new Exception("Export directory out of range");

            IMAGE_EXPORT_DIRECTORY ed = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                (IntPtr)((long)basePtr + expOff), typeof(IMAGE_EXPORT_DIRECTORY));

            if (ed.NumberOfFunctions == 0 || ed.NumberOfFunctions > 0x10000)
                throw new Exception("Suspicious NumberOfFunctions: " + ed.NumberOfFunctions);
            if (ed.NumberOfNames > 0x10000)
                throw new Exception("Suspicious NumberOfNames: " + ed.NumberOfNames);

            uint funcsOff = rva2off(ed.AddressOfFunctions);
            if ((long)funcsOff + (long)ed.NumberOfFunctions * 4 > data.Length)
                throw new Exception("AddressOfFunctions out of range");

            var results = new ExportInfo[ed.NumberOfFunctions];
            for (uint i = 0; i < ed.NumberOfFunctions; i++)
            {
                uint funcRva = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + funcsOff + i * 4));
                results[i] = new ExportInfo { Ordinal = ed.Base + i };
                if (funcRva == 0) { results[i].IsEmpty = true; continue; }
                if (funcRva >= expRva && funcRva < expRva + expSize)
                {
                    results[i].IsForwarder = true;
                    try
                    {
                        uint fwdOff = rva2off(funcRva);
                        int len = 0;
                        while (fwdOff + len < data.Length && data[fwdOff + len] != 0) len++;
                        if (len > 0) results[i].ForwarderTarget = Encoding.ASCII.GetString(data, (int)fwdOff, len);
                    } catch { }
                }
            }

            if (ed.NumberOfNames > 0)
            {
                uint namesOff = rva2off(ed.AddressOfNames);
                uint ordOff   = rva2off(ed.AddressOfNameOrdinals);
                if ((long)namesOff + (long)ed.NumberOfNames * 4 > data.Length ||
                    (long)ordOff   + (long)ed.NumberOfNames * 2 > data.Length)
                    throw new Exception("Name tables out of range");

                var map = new Dictionary<ushort, List<string>>();
                for (uint i = 0; i < ed.NumberOfNames; i++)
                {
                    ushort idx = (ushort)Marshal.ReadInt16((IntPtr)((long)basePtr + ordOff + i * 2));
                    if (idx >= ed.NumberOfFunctions) continue;
                    uint nameRva = (uint)Marshal.ReadInt32((IntPtr)((long)basePtr + namesOff + i * 4));
                    uint nameOff;
                    try { nameOff = rva2off(nameRva); } catch { continue; }
                    if (nameOff >= data.Length) continue;
                    int len = 0;
                    while (nameOff + len < data.Length && data[nameOff + len] != 0) len++;
                    if (len == 0) continue;
                    string nm = Encoding.ASCII.GetString(data, (int)nameOff, len);
                    if (!map.ContainsKey(idx)) map[idx] = new List<string>();
                    map[idx].Add(nm);
                }
                foreach (var kv in map)
                {
                    results[kv.Key].Names = kv.Value.ToArray();
                    results[kv.Key].Name  = kv.Value[0];
                }
            }

            return results;
        }
        finally { h.Free(); }
    }
}
'@

try {
    if (-not ('DllExportReaderV4' -as [type])) {
        Add-Type -TypeDefinition $csharpCode -ErrorAction Stop
        Write-Verbose "Compiled PE export parser."
    }
} catch {
    Write-Error "C# compilation failed: $_"
    exit 1
}

# ---------- Проверка пути ----------
try {
    $resolvedPath = (Resolve-Path -LiteralPath $DllPath -ErrorAction Stop).Path
} catch {
    Write-Error "File not found: $DllPath"
    exit 1
}

# ---------- Парсинг ----------
Write-Host "Analyzing: $resolvedPath" -ForegroundColor Cyan
try {
    $exports = @([DllExportReaderV4]::GetExports($resolvedPath))
} catch {
    Write-Error "Failed to read exports: $_"
    exit 1
}
if ($exports.Count -eq 0) {
    Write-Warning "No exports found."
    exit 0
}

# ---------- Фильтры ----------
$selected = $exports
if ($Ordinals) {
    $set = [System.Collections.Generic.HashSet[uint32]]::new()
    foreach ($o in $Ordinals) { [void]$set.Add([uint32]$o) }
    $selected = $selected | Where-Object { $set.Contains($_.Ordinal) }
}
if ($Names) {
    $lname = @($Names | ForEach-Object { $_.ToLowerInvariant() })
    $selected = $selected | Where-Object {
        @($_.Names | Where-Object { $lname -contains $_.ToLowerInvariant() }).Count -gt 0
    }
}
if ($OnlyNamed)      { $selected = $selected | Where-Object { $_.Names.Length -gt 0 } }
if ($SkipForwarders) { $selected = $selected | Where-Object { -not $_.IsForwarder } }
if ($SkipEmpty)      { $selected = $selected | Where-Object { -not $_.IsEmpty } }

Write-Host ("Found {0} export(s), selected {1}" -f $exports.Count, @($selected).Count) -ForegroundColor Green
Write-Log ("--- Ordinal sweep: " + $resolvedPath + " ---") 'Cyan'
Write-Log ("Ordinals={0} Named={1} Forwarders={2} Empty={3}" -f `
    $exports.Count, ($exports | ? {$_.Names.Length -gt 0}).Count, `
    ($exports | ? {$_.IsForwarder}).Count, ($exports | ? {$_.IsEmpty}).Count) 'DarkGray'

# ---------- Режим "только список" ----------
if ($NoCall -or -not $Dangerous) {
    foreach ($e in $selected) {
        $names = if ($e.Names.Length) { $e.Names -join '; ' } else { '<none>' }
        $mark  = @()
        if ($e.IsEmpty)     { $mark += 'EMPTY' }
        if ($e.IsForwarder) { $mark += "FWD→$($e.ForwarderTarget)" }
        Write-Host ("#{0,5}  {1,-40}  {2}" -f $e.Ordinal, $names, ($mark -join ' '))
    }
    if (-not $Dangerous) {
        Write-Host ""
        Write-Host "Не запускаю экспорты: добавьте -Dangerous (исполняет код DLL) или -NoCall (уже включено)." -ForegroundColor Yellow
    }
    if ($OutCsv)  { $selected | Select-Object Ordinal,Name,@{n='Names';e={$_.Names -join ';'}},IsForwarder,ForwarderTarget,IsEmpty | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv }
    if ($OutJson) { $selected | Select-Object Ordinal,Name,@{n='Names';e={$_.Names}},IsForwarder,ForwarderTarget,IsEmpty | ConvertTo-Json -Depth 4 | Set-Content -Path $OutJson -Encoding UTF8 }
    Write-Host "Log: $LogPath" -ForegroundColor Cyan
    exit 0
}

# ---------- Свип ----------
if (-not $PSCmdlet.ShouldProcess($resolvedPath, "Вызвать $($selected.Count) экспортов через rundll32.exe")) {
    exit 0
}

$results = New-Object System.Collections.Generic.List[object]
$rundll32 = Join-Path $env:SystemRoot 'System32\rundll32.exe'

try {
    $i = 0
    foreach ($exp in $selected) {
        $i++
        $ord    = $exp.Ordinal
        $names  = if ($exp.Names.Length) { $exp.Names -join '; ' } else { '<none>' }
        $before = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $before[$_.Id] = $_.ProcessName }

        Write-Log ("[{0}] #{1} {2} — calling..." -f (Get-Date -Format 'HH:mm:ss'), $ord, $names) 'Yellow'

        $args  = @("`"$resolvedPath`"", "#$ord")
        $spawned = New-Object System.Collections.Generic.HashSet[int]
        $timedOut = $false
        $exitCode = $null
        $err = $null
        $proc = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $proc = Start-Process -FilePath $rundll32 -ArgumentList $args -PassThru -WindowStyle Hidden -ErrorAction Stop
            $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
            while (-not $proc.HasExited -and [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 100
                Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { -not $before.ContainsKey($_.Id) -and $_.Id -ne $proc.Id } |
                    ForEach-Object { [void]$spawned.Add($_.Id) }
            }
            if (-not $proc.HasExited) {
                $timedOut = $true
                try { $proc.Kill($true) } catch { try { $proc.Kill() } catch { } }
            } else {
                $proc.Refresh()
                $exitCode = $proc.ExitCode
            }
        } catch {
            $err = $_.Exception.Message
        } finally {
            $sw.Stop()
            # финальный сбор порождённых процессов
            Get-Process -ErrorAction SilentlyContinue |
                Where-Object { -not $before.ContainsKey($_.Id) -and ($null -eq $proc -or $_.Id -ne $proc.Id) } |
                ForEach-Object { [void]$spawned.Add($_.Id) }
        }

        $spawnedNames = @()
        foreach ($pidNew in $spawned) {
            $p = Get-Process -Id $pidNew -ErrorAction SilentlyContinue
            if ($p) { $spawnedNames += "{0}({1})" -f $p.ProcessName, $pidNew }
        }

        $status = if ($err) { "ERROR: $err" }
                  elseif ($timedOut) { "TIMEOUT" }
                  else { "exit=$exitCode" }
        $line = "  -> $status, elapsed=$([int]$sw.Elapsed.TotalMilliseconds)ms"
        if ($spawnedNames.Count) { $line += " | SPAWNED: $($spawnedNames -join ', ')" }
        Write-Log $line $(if ($err -or $timedOut) { 'Red' } else { 'Gray' })

        $results.Add([pscustomobject]@{
            Ordinal         = $ord
            Name            = if ($exp.Name) { $exp.Name } else { $null }
            Names           = $exp.Names -join ';'
            IsForwarder     = $exp.IsForwarder
            ForwarderTarget = $exp.ForwarderTarget
            IsEmpty         = $exp.IsEmpty
            TimedOut        = $timedOut
            ExitCode        = $exitCode
            Error           = $err
            Spawned         = ($spawnedNames -join ',')
            ElapsedMs       = [int]$sw.Elapsed.TotalMilliseconds
        })

        if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
    }
}
finally {
    # добиваем оставшиеся rundll32, чтобы не оставлять сирот
    Get-Process rundll32 -ErrorAction SilentlyContinue | ForEach-Object {
        try { $_.Kill() } catch { }
    }
}

# ---------- Итог ----------
$ok       = @($results | Where-Object { -not $_.TimedOut -and -not $_.Error })
$timedOut = @($results | Where-Object { $_.TimedOut })
$errored  = @($results | Where-Object { $_.Error })
$spawners = @($results | Where-Object { $_.Spawned })

Write-Host ""
Write-Host "==== Summary ====" -ForegroundColor Cyan
Write-Host ("Tested     : {0}" -f $results.Count)
Write-Host ("Normal exit: {0}" -f $ok.Count)      -ForegroundColor Green
Write-Host ("Timeouts   : {0}" -f $timedOut.Count) -ForegroundColor Yellow
Write-Host ("Errors     : {0}" -f $errored.Count)  -ForegroundColor Red
Write-Host ("Spawned    : {0} export(s) launched child procs" -f $spawners.Count) -ForegroundColor Magenta


if ($OutCsv)  { $results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv;  Write-Host "CSV : $OutCsv" }
if ($OutJson) { $results | ConvertTo-Json -Depth 4 | Set-Content -Path $OutJson -Encoding UTF8; Write-Host "JSON: $OutJson" }
Write-Host "Log : $LogPath" -ForegroundColor Cyan
```

> ⚠️ **Это потенциально опасный скрипт.** С `-Dangerous` он **исполняет код из
> анализируемой DLL**. Запускайте только в изолированной среде (VM, sandbox, disposable
> VM) и только с собственными/тестовыми бинарниками. Без `-Dangerous` (или с `-NoCall`)
> скрипт работает как *read-only*-анализатор таблицы экспортов.

## Возможности

- Ручной разбор **PE32 и PE32+** без сторонних библиотек (C# через `Add-Type`).
- **Определение forwarder-экспортов** (`AddressOfFunctions[i]` указывает внутрь export directory).
- **Определение «пустых» ординалов** (`AddressOfFunctions[i] == 0`) — по умолчанию
  они тоже вызываются, но их можно пропустить через `-SkipEmpty`.
- **Сбор всех имён** одного ординала (`Name` = первое, `Names` = полный список).
- **Фильтры**: по конкретным ординалам (`-Ordinals`), именам (`-Names`),
  только именованные (`-OnlyNamed`), без forwarder'ов (`-SkipForwarders`).
- **Вызов через `rundll32.exe`** с таймаутом на каждый ординал.
- **Обнаружение порождённых процессов** на всём протяжении выполнения `rundll32`
  (калькулятор, `cmd.exe`, `powershell.exe` и т.п.) — с PID’ами в отчёте.
- **`-WhatIf` / `-Confirm`** (через `SupportsShouldProcess`), поскольку действие
  необратимо.
- **`-NoCall`** — только вывести таблицу экспортов, ничего не запускать.
- **Экспорт результатов** в CSV (`-OutCsv`) и JSON (`-OutJson`).
- **Автоматическая уборка**: если пользователь прервал работу (Ctrl+C), скрипт
  в `finally` прибивает «осиротевшие» `rundll32.exe`.
- Понятный лог в `DllExportRun_<timestamp>.log` рядом со скриптом.

## Требования

- Windows, PowerShell **5.1+** (для `-ThrottleLimit` и параллельного `-Parallel` —
  PowerShell 7+; в этой версии параметр объявлен, но используйте `-ThrottleLimit 1`
  на 5.1).
- .NET Framework 4.x / .NET 6+ (для `Add-Type` с C#).
- `rundll32.exe` в `%SystemRoot%\System32\` (есть всегда на Windows).

## Установка

```powershell
Unblock-File .\DllExportSweep.ps1
Set-ExecutionPolicy -Scope Process Bypass
```

## Использование

```powershell
.\DllExportSweep.ps1 -DllPath <path> [-Dangerous | -NoCall] [опции]
```

### Параметры

| Параметр | По умолчанию | Описание |
|---|---|---|
| `-DllPath <string>` | — (обязателен) | Путь к анализируемой DLL/EXE. |
| `-Dangerous` | off | Подтверждает запуск экспортов. Без него и без `-NoCall` — только список. |
| `-NoCall` | off | Ничего не запускать, только вывести таблицу экспортов. |
| `-TimeoutSeconds <int>` | `10` | Таймаут на один `rundll32`. |
| `-DelayMs <int>` | `200` | Пауза между вызовами. |
| `-Ordinals <int[]>` | — | Ограничить набор ординалов (например `-Ordinals 1,5,100`). |
| `-Names <string[]>` | — | Ограничить набор по именам экспортов. |
| `-OnlyNamed` | off | Пропустить ординал-онли записи. |
| `-SkipForwarders` | off | Пропустить forwarder-экспорты. |
| `-SkipEmpty` | off | Пропустить «пустые» ординалы. |
| `-ThrottleLimit <int>` | `1` | (только PS 7+) одновременных `rundll32`; в этой реализации пока не используется для параллелизма, оставлен как заглушка. |
| `-OutCsv <path>` | — | Сохранить результаты в CSV. |
| `-OutJson <path>` | — | Сохранить результаты в JSON. |
| `-LogPath <path>` | `<script dir>/DllExportRun_<ts>.log` | Путь к логу. |

### Примеры

Только посмотреть экспорты (безопасно):

```powershell
.\DllExportSweep.ps1 -DllPath .\target.dll -NoCall
```

Только именованные экспорты, без forwarder’ов, вывод в CSV:

```powershell
.\DllExportSweep.ps1 -DllPath .\test.dll -Dangerous -OnlyNamed -SkipForwarders -OutCsv .\res.csv
```

Проверить конкретные ординалы с коротким таймаутом:

```powershell
.\DllExportSweep.ps1 -DllPath .\test.dll -Dangerous -Ordinals 1,10,100 -TimeoutSeconds 3
```

Вызов с подтверждением через `-WhatIf`:

```powershell
.\DllExportSweep.ps1 -DllPath .\test.dll -Dangerous -WhatIf
```

## Поведение

1. Скрипт читает PE-заголовок и таблицу экспортов **в память** (никакой загрузки DLL в
   процесс PowerShell).
2. Применяются фильтры (если заданы).
3. Если указан `-NoCall` или не указан `-Dangerous` — печатается таблица и скрипт
   завершается (без исполнения кода).
4. Иначе для каждого выбранного ординала:
   - стартует `rundll32.exe "<path>", #<ord>`;
   - в цикле раз в 100 мс снимается снимок процессов и фиксируются **новые PID’ы**,
     отличные от `rundll32`;
   - по истечении `-TimeoutSeconds` процесс убивается (`Kill($true)` в PS 7+,
     `Kill()` в 5.1);
   - после завершения — `Refresh()` и считывание `ExitCode`;
   - в лог и в `$results` пишется ординал, имена, флаг forwarder’а, статус
     (exit / timeout / error), список порождённых процессов, время выполнения.
5. В `finally` — kill всех оставшихся `rundll32.exe`, чтобы не плодить сирот.
6. Печатается сводка, при необходимости — CSV/JSON.

## Ограничения и нюансы

- `rundll32` вызывает функцию как `void CALLBACK f(HWND, HINSTANCE, LPSTR, INT)`.
  **Большинство реальных экспортов имеют другую сигнатуру** — это гарантированный
  крэш (`ACCESS_VIOLATION`). Скрипт не отличает «упало, потому что сигнатура не та»
  от «упало, потому что баг в DLL» — оба случая дадут ненулевой exit code
  (либо таймаут из-за WER-диалога).
- **Отключите Windows Error Reporting** или используйте VM, иначе на каждый крэш
  будет висеть диалог, а скрипт будет ждать таймаут.
- **Экспорт с `IsForwarder`** сам по себе не является функцией — `rundll32` по нему
  упадёт предсказуемо. Для forwarder’ов полезнее смотреть `ForwarderTarget` в CSV/JSON.
- **`ExitCode`** у `rundll32` часто `0xC0000005` (`0xC0000005` → «access violation»),
  `0xC0000139` (точка входа не найдена) — трактуйте как «функция не подходит под
  сигнатуру rundll32», а не как успех/неуспех.
- **Порождённые процессы** ловятся снимками раз в 100 мс; короткоживущий
  (`<100 мс`) дочерний процесс может быть пропущен. Для повышения точности
  уменьшите интервал или используйте WMI `__InstanceCreationEvent` (вне области этого
  скрипта).
- **Очень большие таблицы экспортов** (`> 4096`) с таймаутом по умолчанию займут
  часы. Сужайте `-Ordinals`/`-Names` или уменьшайте `-TimeoutSeconds`.
- `ThrottleLimit` объявлен, но в текущей версии не реализован (последовательный цикл).
  Параллельный вариант легко добавить через `ForEach-Object -Parallel` (PS 7+).

## Коды возврата

| Код | Причина |
|---|---|
| `0` | Успех (в т.ч. режим `-NoCall`). |
| `1` | Не удалось скомпилировать C#-парсер, прочитать файл или таблицу экспортов. |
| `2` | Ошибка параметров. |

## Предупреждение

Скрипт **не является** инструментом аудита безопасности и не гарантирует
безопасного исполнения. Код из DLL исполняется с правами вашей учётной записи.
Не запускайте на подозрительных/непроверенных бинарниках вне изолированной среды.
