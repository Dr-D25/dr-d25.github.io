# VM / Sandbox Detector

Скрипт на Python для обнаружения виртуальных машин и песочниц (sandbox) по набору независимых проверок. Работает на Windows, Linux и macOS. Использует взвешенную оценку рисков вместо бинарного «да/нет», что снижает вероятность ложных срабатываний.


```python
import os
import sys
import platform
import re
import subprocess
import uuid
import time
import ctypes
import ctypes.wintypes
import psutil

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


def check_mac_addresses():
    vm_prefixes = [
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56",
        "08:00:27", "52:54:00", "00:15:5D", "00:16:3E",
        "00:1C:42", "00:03:FF", "00:0F:4B", "00:21:F6",
    ]
    mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    mac_upper = mac.upper()
    for prefix in vm_prefixes:
        if mac_upper.startswith(prefix.upper()):
            return True, f"VM MAC: {mac} (prefix {prefix})"
    return False, None


def check_processes():
    vm_procs = {
        'vboxservice', 'vboxtray', 'vmtoolsd', 'vmwaretrat', 'vmwareuser',
        'vmacthlp', 'qemu-ga', 'qemu-ga.exe', 'xenservice', 'prl_cc',
        'prl_tools', 'vmusrvc', 'vmsrvc', 'dvzsnmp', 'vboxservice.exe',
        'vmtoolsd.exe', 'vmwaretrat.exe', 'vboxclient', 'vboxsf',
    }
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name'].lower()
            if name in vm_procs:
                return True, f"VM process: {proc.info['name']}"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False, None


def check_dmi_linux():
    keywords = ['virtualbox', 'vmware', 'kvm', 'qemu', 'xen',
                'hyper-v', 'bochs', 'parallels', 'bhyve', 'openstack']
    paths = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/chassis_vendor",
    ]
    for path in paths:
        try:
            with open(path, 'r') as f:
                data = f.read().lower()
                for kw in keywords:
                    if kw in data:
                        return True, f"DMI {path}: {kw}"
        except (FileNotFoundError, PermissionError):
            continue
    return False, None


def check_dmi_windows():
    if HAS_WMI:
        try:
            c = wmi.WMI()
            for board in c.Win32_BaseBoard():
                text = f"{board.Manufacturer} {board.Product}".lower()
                for kw in ['virtual', 'vmware', 'qemu', 'xen', 'vbox', 'hyper-v', 'parallels']:
                    if kw in text:
                        return True, f"WMI BaseBoard: {kw} ({text.strip()})"
        except Exception:
            pass
    try:
        output = subprocess.check_output(
            ["wmic", "baseboard", "get", "manufacturer,product"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors='ignore').lower()
        for kw in ['virtual', 'vmware', 'qemu', 'xen', 'vbox', 'hyper-v', 'parallels']:
            if kw in output:
                return True, f"WMIC BaseBoard: {kw}"
    except Exception:
        pass
    try:
        output = subprocess.check_output(
            ["wmic", "bios", "get", "manufacturer,version"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors='ignore').lower()
        for kw in ['virtual', 'vmware', 'qemu', 'xen', 'vbox', 'hyper-v', 'parallels']:
            if kw in output:
                return True, f"WMIC BIOS: {kw}"
    except Exception:
        pass
    return False, None


def check_disks():
    try:
        for part in psutil.disk_partitions(all=True):
            dev = part.device.lower()
            mnt = part.mountpoint.lower()
            if any(k in dev or k in mnt for k in ['vbox', 'vmware', 'virtual', 'qemu', 'xvd']):
                return True, f"Virtual disk: {part.device}"
    except Exception:
        pass
    return False, None


def check_cpuid_linux():
    try:
        with open("/proc/cpuinfo", 'r') as f:
            data = f.read().lower()
            if 'hypervisor' in data:
                return True, "CPU hypervisor flag (Linux)"
    except (FileNotFoundError, PermissionError):
        pass
    try:
        result = subprocess.check_output(
            ["systemd-detect-virt"], stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors='ignore').strip()
        if result and result != "none":
            return True, f"systemd-detect-virt: {result}"
    except Exception:
        pass
    return False, None


def check_cpuid_windows():
    if platform.machine().endswith('64'):
        class CPUIDStruct(ctypes.Structure):
            _fields_ = [("eax", ctypes.c_uint),
                        ("ebx", ctypes.c_uint),
                        ("ecx", ctypes.c_uint),
                        ("edx", ctypes.c_uint)]

        def cpuid_leaf(leaf):
            result = CPUIDStruct()
            try:
                ctypes.windll.kernel32.__cpuid(ctypes.byref(result), leaf)
            except Exception:
                return None
            return result

        leaf1 = cpuid_leaf(1)
        if leaf1 and (leaf1.ecx & (1 << 31)):
            vendor_leaf = cpuid_leaf(0)
            vendor = ""
            if vendor_leaf:
                try:
                    buf = ctypes.create_string_buffer(12)
                    ctypes.memmove(buf, ctypes.byref(vendor_leaf.ebx), 4)
                    ctypes.memmove(ctypes.byref(buf, 4), ctypes.byref(vendor_leaf.edx), 4)
                    ctypes.memmove(ctypes.byref(buf, 8), ctypes.byref(vendor_leaf.ecx), 4)
                    vendor = buf.value.decode(errors='ignore')
                except Exception:
                    pass
            return True, f"CPUID hypervisor bit set (vendor={vendor or 'unknown'})"
    return False, None


def check_drivers_and_files():
    vm_files = [
        r"C:\Windows\System32\drivers\vmci.sys",
        r"C:\Windows\System32\drivers\vmhgfs.sys",
        r"C:\Windows\System32\drivers\vmmouse.sys",
        r"C:\Windows\System32\drivers\vboxguest.sys",
        r"C:\Windows\System32\drivers\vboxmouse.sys",
        r"C:\Windows\System32\drivers\vboxsf.sys",
        r"C:\Windows\System32\drivers\vboxvideo.sys",
        r"C:\Windows\System32\drivers\qemu-ga.sys",
        r"C:\Program Files\VMware\VMware Tools",
        r"C:\Program Files (x86)\VMware\VMware Tools",
        r"C:\Program Files\Oracle\VirtualBox Guest Additions",
        r"C:\Program Files (x86)\Oracle\VirtualBox Guest Additions",
        "/usr/bin/VBoxClient",
        "/usr/bin/VBoxService",
        "/usr/bin/vmtoolsd",
        "/usr/sbin/vboxadd-service",
        "/etc/vmware-tools",
        "/usr/lib/vmware-tools",
        "/dev/vboxguest",
        "/dev/vmci",
        "/dev/virtio-ports",
    ]
    for p in vm_files:
        if os.path.exists(p):
            return True, f"VM file/driver: {p}"
    return False, None


def check_registry_windows():
    if not HAS_WINREG:
        return False, None
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmci"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmtools"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmhgfs"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\IDE\CdRomVen*VMware*"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\SCSI\Disk*VMware*"),
        (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"),
    ]
    for root, path in keys:
        try:
            winreg.OpenKey(root, path)
            return True, f"Registry key: {path}"
        except OSError:
            continue
    return False, None


def check_wmi_gpu():
    if not HAS_WMI:
        return False, None
    try:
        c = wmi.WMI()
        for gpu in c.Win32_VideoController():
            name = (gpu.Name or "").lower()
            vram = getattr(gpu, 'AdapterRAM', 0) or 0
            if any(k in name for k in ['vmware svga', 'virtualbox', 'microsoft basic render',
                                       'microsoft hyper-v video', 'qxl', 'virtio']):
                return True, f"Virtual GPU: {gpu.Name} (VRAM={vram})"
            if vram > 0 and vram < 33554432:
                return True, f"Suspiciously low VRAM: {gpu.Name} ({vram} bytes)"
    except Exception:
        pass
    return False, None


def check_wmi_system():
    if not HAS_WMI:
        return False, None
    try:
        c = wmi.WMI()
        for cs in c.Win32_ComputerSystem():
            text = f"{cs.Manufacturer} {cs.Model}".lower()
            for kw in ['virtual', 'vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v', 'parallels']:
                if kw in text:
                    return True, f"WMI ComputerSystem: {kw} ({text.strip()})"
        for bios in c.Win32_BIOS():
            text = f"{bios.Manufacturer} {bios.Version}".lower()
            for kw in ['virtual', 'vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v', 'parallels']:
                if kw in text:
                    return True, f"WMI BIOS: {kw} ({text.strip()})"
    except Exception:
        pass
    return False, None


def check_timing_cpuid():
    if platform.system() == "Linux":
        try:
            start = time.perf_counter_ns()
            with open("/proc/cpuinfo", 'r') as f:
                f.read(1)
            elapsed = time.perf_counter_ns() - start
            if elapsed > 50_000_000:
                return True, f"Abnormally slow /proc/cpuinfo read: {elapsed/1e6:.2f}ms"
        except Exception:
            pass
    return False, None


def check_timing_sleep():
    try:
        t0 = time.perf_counter()
        time.sleep(0.1)
        elapsed = time.perf_counter() - t0
        if elapsed < 0.095:
            return True, f"Time acceleration: sleep(0.1) took {elapsed*1000:.1f}ms"
        if elapsed > 0.5:
            return True, f"Time slowdown: sleep(0.1) took {elapsed*1000:.1f}ms"
    except Exception:
        pass
    return False, None


def check_timing_rdtsc_drift():
    if platform.system() == "Windows":
        try:
            t0 = time.perf_counter()
            time.sleep(0.05)
            t1 = time.perf_counter()
            wall = (t1 - t0) * 1000
            cpu0 = time.process_time()
            time.sleep(0.05)
            cpu1 = time.process_time()
            cpu_delta = (cpu1 - cpu0) * 1000
            if cpu_delta > wall * 2 and wall > 10:
                return True, f"Timer drift: wall={wall:.1f}ms cpu={cpu_delta:.1f}ms"
        except Exception:
            pass
    return False, None


def check_hardware_specs():
    try:
        cpu_cores = psutil.cpu_count(logical=True)
        ram = psutil.virtual_memory().total
        if cpu_cores <= 2:
            return True, f"Low CPU core count: {cpu_cores}"
        if ram < 4 * (1024**3):
            return True, f"Low RAM: {ram / (1024**3):.1f} GB"
        try:
            disk = psutil.disk_usage('/')
            if disk.total < 80 * (1024**3):
                return True, f"Small disk: {disk.total / (1024**3):.1f} GB"
        except Exception:
            pass
    except Exception:
        pass
    return False, None


def check_username_hostname():
    try:
        user = os.getenv('USER') or os.getenv('USERNAME') or ''
        host = platform.node() or ''
        suspicious = ['sandbox', 'malware', 'virus', 'analyst', 'cuckoo',
                      'vmware', 'virtual', 'vbox', 'test', 'admin', 'user',
                      'workstation-1', 'win-', 'desktop-']
        combined = f"{user} {host}".lower()
        for kw in suspicious:
            if kw in combined:
                return True, f"Suspicious user/host: {user}@{host} ({kw})"
    except Exception:
        pass
    return False, None


def check_clipboard_recent_docs():
    if platform.system() == "Windows" and HAS_WMI:
        try:
            c = wmi.WMI()
            recent = c.Win32_RecentFile()
            if not recent:
                return True, "No recent documents (sandbox artifact)"
        except Exception:
            pass
    return False, None


def check_input_activity():
    if platform.system() == "Windows":
        try:
            last_input = ctypes.windll.user32.GetLastInputInfo()
            tick = ctypes.windll.kernel32.GetTickCount()
            idle_ms = tick - last_input
            if idle_ms > 300_000:
                return True, f"No user input for {idle_ms/1000:.0f}s"
        except Exception:
            pass
    return False, None


def check_pci_vendor():
    if platform.system() == "Linux":
        try:
            for dev in os.listdir("/sys/bus/pci/devices"):
                try:
                    vendor_file = f"/sys/bus/pci/devices/{dev}/vendor"
                    with open(vendor_file) as f:
                        vid = f.read().strip().lower()
                    if vid in ("0x15ad", "0x80ee", "0x1af4", "0x5853"):
                        return True, f"VM PCI vendor: {vid} on {dev}"
                except Exception:
                    continue
        except Exception:
            pass
    return False, None


def check_usb_history():
    if platform.system() == "Windows" and HAS_WINREG:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
        except OSError:
            return True, "No USBSTOR history (sandbox artifact)"
        except Exception:
            pass
    return False, None


def check_macos():
    if platform.system() != "Darwin":
        return False, None
    try:
        output = subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.features"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors='ignore').upper()
        if "VMM" in output:
            return True, "macOS VMM CPU feature flag"
    except Exception:
        pass
    try:
        output = subprocess.check_output(
            ["sysctl", "-n", "kern.hv_vmm_present"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors='ignore').strip()
        if output == "1":
            return True, "macOS hypervisor present (kern.hv_vmm_present=1)"
    except Exception:
        pass
    try:
        output = subprocess.check_output(
            ["ioreg", "-l"],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode(errors='ignore').lower()
        for kw in ['virtualbox', 'vmware', 'parallels', 'qemu', 'virtual']:
            if kw in output:
                return True, f"macOS ioreg: {kw}"
    except Exception:
        pass
    return False, None


def main():
    system = platform.system()
    print(f"[i] Platform: {system}")
    print(f"[i] Python: {platform.python_version()}")
    print()

    results = []
    score = 0
    weight = 10

    def add(result):
        nonlocal score
        detected, detail = result
        if detected:
            score += weight
            print(f"[!] {detail}")
        results.append(detected)

    checks = [
        check_mac_addresses,
        check_processes,
        check_disks,
        check_drivers_and_files,
        check_timing_sleep,
        check_timing_rdtsc_drift,
        check_hardware_specs,
        check_username_hostname,
        check_clipboard_recent_docs,
        check_input_activity,
        check_usb_history,
    ]

    if system == "Linux":
        checks += [
            check_dmi_linux,
            check_cpuid_linux,
            check_timing_cpuid,
            check_pci_vendor,
        ]
    elif system == "Windows":
        checks += [
            check_dmi_windows,
            check_cpuid_windows,
            check_registry_windows,
            check_wmi_gpu,
            check_wmi_system,
        ]
    elif system == "Darwin":
        checks += [check_macos]

    for check in checks:
        try:
            add(check())
        except Exception as e:
            print(f"[x] {check.__name__}: {e}")

    print()
    total = len(results)
    detected_count = sum(1 for r in results if r)
    print(f"[i] Checks: {detected_count}/{total} positive, weighted score: {score}")

    if score >= 20 or (total > 0 and detected_count / total >= 0.4):
        print("\n[!] VIRTUAL MACHINE / SANDBOX DETECTED")
    else:
        print("\n[+] No virtualization detected.")


if __name__ == "__main__":
    main()
```


## Возможности

Скрипт выполняет набор проверок, сгруппированных по категориям. Каждая успешная проверка добавляет вес к итоговому счёту.

### Сетевые идентификаторы
- **MAC-адреса** — сравнение OUI префикса сетевого адаптера с известными диапазонами VMware, VirtualBox, QEMU/KVM, Hyper-V, Xen, Parallels, bhyve.

### Процессы
- Поиск запущенных процессов гостевых дополнений: `VBoxService`, `VBoxTray`, `VBoxClient`, `vmtoolsd`, `vmwareuser`, `qemu-ga`, `xenservice`, `prl_cc`, `vboxsf` и др.

### Файлы и драйверы
- Проверка наличия драйверов (`vmci.sys`, `vmhgfs.sys`, `vmmouse.sys`, `vboxguest.sys`, `vboxmouse.sys`, `vboxsf.sys`, `vboxvideo.sys`, `qemu-ga.sys`).
- Проверка каталогов установки VMware Tools и VirtualBox Guest Additions.
- Проверка устройств `/dev/vboxguest`, `/dev/vmci`, `/dev/virtio-ports`, путей `/etc/vmware-tools`, `/usr/lib/vmware-tools`.

### DMI / SMBIOS
- **Linux** — чтение `/sys/class/dmi/id/*` (`product_name`, `sys_vendor`, `board_vendor`, `bios_vendor`, `chassis_vendor`) и поиск ключевых слов.
- **Windows** — WMI `Win32_BaseBoard`, `Win32_BIOS`, `Win32_ComputerSystem`, а также fallback через `wmic`.

### CPUID / гипервизор
- **Linux** — флаг `hypervisor` в `/proc/cpuinfo`, вызов `systemd-detect-virt`.
- **Windows** — прямой вызов `CPUID` листа `1`, проверка бита `ECX[31]` и чтение вендора гипервизора из листа `0`.
- **macOS** — `machdep.cpu.features` (флаг `VMM`), `kern.hv_vmm_present`, поиск по `ioreg`.

### Реестр (Windows)
- Проверка ключей `SOFTWARE\VMware, Inc.\VMware Tools`, `SOFTWARE\Oracle\VirtualBox Guest Additions`, `SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`, служб `vmci`, `VBoxGuest`, `vmtools`, `vmhgfs`.
- Проверка `Enum\IDE\CdRomVen*VMware*`, `Enum\SCSI\Disk*VMware*`, `HARDWARE\DEVICEMAP\Scsi`.

### Оборудование
- **GPU** — имя видеоадаптера (`VMware SVGA`, `VirtualBox`, `Microsoft Basic Render`, `Hyper-V Video`, `qxl`, `virtio`) и аномально малый объём видеопамяти.
- **PCI vendors (Linux)** — идентификаторы `0x15ad` (VMware), `0x80ee` (VirtualBox), `0x1af4` (virtio), `0x5853` (Xen).
- **Спецификации** — слишком малое число ядер CPU (≤ 2), малый объём RAM (< 4 ГБ), маленький диск (< 80 ГБ).

### Временные аномалии
- **sleep drift** — `time.sleep(0.1)` выполняется быстрее 95 мс (ускорение времени) или дольше 500 мс (замедление).
- **timer drift** — расхождение между `perf_counter` и `process_time` во время сна.
- **медленное чтение** `/proc/cpuinfo` (> 50 мс) — признак эмуляции или трассировки.

### Артефакты песочницы
- Подозрительные имена пользователя или хоста (`sandbox`, `malware`, `analyst`, `cuckoo`, `vmware`, `vbox`, `win-`, `desktop-` и т. п.).
- Отсутствие списка недавних документов (`Win32_RecentFile`).
- Отсутствие истории USB-устройств (`USBSTOR` в реестре).
- Длительное отсутствие ввода пользователя (> 5 минут простоя).

## Требования

- Python 3.8+
- `psutil` — обязательная зависимость
- `WMI` (`pip install WMI`) — опционально, только для Windows; при отсутствии используются резервные проверки через `wmic`
- `pywin32` — требуется для `winreg` на Windows

Установка зависимостей:

```bash
pip install psutil
pip install WMI pywin32  # только Windows
```
