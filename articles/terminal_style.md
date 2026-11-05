## Вариант 1 — C2 Console


```zsh
PROMPT=$'
%B%F{196}C2::%b%f %F{160}%~%f
%F{88}█%f '
```

```bash
PS1='\n\
\[\e[1;31m\]C2::\[\e[0m\] \[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]█\[\e[0m\] '
```

### Выглядит:
```
C2:: ~/payloads
█
```

## Вариант 2 — MALWARE LAB


```zsh
PROMPT=$'
%B%F{196}◢ MALWARE LAB ◣%b%f
%F{160}%~%f
%F{88}▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]◢ MALWARE LAB ◣\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]▶\[\e[0m\] '
```

### Выглядит:
```
◢ MALWARE LAB ◣
~/samples
▶
```
## Вариант 3 — REVERSE ENGINEERING

```zsh
PROMPT=$'
%B%F{196}◢ REVERSE ENGINEERING ◣%b%f
%F{240}%~%f
%F{160}❯%f '
```

```bash
PS1='\n\
\[\e[1;31m\]◢ REVERSE ENGINEERING ◣\[\e[0m\]
\[\e[38;5;240m\]\w\[\e[0m\]
\[\e[38;5;160m\]❯\[\e[0m\] '
```

### Выглядит:
```
◢ REVERSE ENGINEERING ◣
~/projects/crackme
❯
```
## Вариант 4 — IDA / Debugger

```zsh
PROMPT=$'
%B%F{208}IDA DEBUG%b%f
%F{240}RIP:0x%08>.$$
%F{160}%~
%F{196}▶%f '
```

```bash
PS1='\n\
\[\e[1;33m\]IDA DEBUG\[\e[0m\]
\[\e[38;5;240m\]RIP:0x$$\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]▶\[\e[0m\] '
```

### Выглядит:
```
IDA DEBUG
RIP:0x4812
~/crackme
▶
```

## Вариант 5 — THREAT INTELLIGENCE

```zsh
PROMPT=$'
%B%F{196}╔══ THREAT INTELLIGENCE ══╗%b%f
%F{240}USER:%n HOST:%m
PATH:%~
%F{196}╚══▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ THREAT INTELLIGENCE ══╗\[\e[0m\]
\[\e[38;5;240m\]USER:\u HOST:\h\[\e[0m\]
\[\e[38;5;160m\]PATH:\w\[\e[0m\]
\[\e[1;31m\]╚══▶\[\e[0m\] '
```

### Выглядит:
```
╔══ THREAT INTELLIGENCE ══╗
USER:analyst HOST:kali
PATH:~/samples
╚══▶
```

## Вариант 6 — CPU STATE

```zsh
PROMPT=$'
%B%F{196}RAX RBX RCX RDX%b%f
%F{240}00  00  00  00
%F{160}%~
%F{196}▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]RAX RBX RCX RDX\[\e[0m\]
\[\e[38;5;240m\]00  00  00  00\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]▶\[\e[0m\] '
```

### Выглядит:
```
RAX RBX RCX RDX
00  00  00  00
~/reverse
▶
```

## 7. BLACK OPS TERMINAL

```zsh
PROMPT=$'
%B%F{196}◢ BLACK OPS ◣%b%f
%F{240}%~%f
%F{88}█%f '
```

```bash
PS1='\n\
\[\e[1;31m\]◢ BLACK OPS ◣\[\e[0m\]
\[\e[38;5;240m\]\w\[\e[0m\]
\[\e[38;5;88m\]█\[\e[0m\] '
```
### Выглядит
```
◢ BLACK OPS ◣
~/operations
█
```
## 8. MALWARE SANDBOX

```zsh
PROMPT=$'
%B%F{196}[ SANDBOX ]%b%f
%F{160}%~%f
%F{196}>%f '
```

```bash
PS1='\n\
\[\e[1;31m\][ SANDBOX ]\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]>\[\e[0m\] '
```
### Выглядит
```
[ SANDBOX ]
~/samples
>
```
## 9. ROOT ACCESS

```zsh
PROMPT=$'
%B%F{196}ROOT ACCESS%b%f
%F{160}%~%f
%F{88}#%f '
```

```bash
PS1='\n\
\[\e[1;31m\]ROOT ACCESS\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]#\[\e[0m\] '
```
### Выглядит
```
ROOT ACCESS
/root/exploits
#
```

## 10. EXPLOIT DEVELOPMENT

```zsh
PROMPT=$'
%B%F{196}EXPLOIT DEV%b%f
%F{240}%~%f
%F{208}0x%08>.$$
%F{196}▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]EXPLOIT DEV\[\e[0m\]
\[\e[38;5;240m\]\w\[\e[0m\]
\[\e[38;5;208m\]0x$$\[\e[0m\]
\[\e[38;5;196m\]▶\[\e[0m\] '
```
### Выглядит
```
EXPLOIT DEV
~/pwn
0x4812
▶
```

## 11. KERNEL DEBUG

```zsh
PROMPT=$'
%B%F{196}KERNEL DEBUG%b%f
%F{240}PID:%$ UID:%# 
%F{160}%~
%F{196}dbg> '
```

```bash
PS1='\n\
\[\e[1;31m\]KERNEL DEBUG\[\e[0m\]
\[\e[38;5;240m\]PID:$$ UID:$UID\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]dbg>\[\e[0m\] '
```
### Выглядит
```
KERNEL DEBUG
PID:4321 UID:1000
~/drivers
dbg>
```

## 12. HEX VIEWER

```zsh
PROMPT=$'
%B%F{196}HEX VIEWER%b%f
%F{240}DE AD BE EF
%F{160}%~
%F{196}:%f '
```

```bash
PS1='\n\
\[\e[1;31m\]HEX VIEWER\[\e[0m\]
\[\e[38;5;240m\]DE AD BE EF\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]:\[\e[0m\] '
```
### Выглядит
```
HEX VIEWER
DE AD BE EF
~/dump
:
```
## 13. REVERSE SHELL

```zsh
PROMPT=$'
%B%F{196}REVERSE SHELL%b%f
%F{160}%~
%F{88}$%f '
```

```bash
PS1='\n\
\[\e[1;31m\]REVERSE SHELL\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]\$\[\e[0m\] '
```
### Выглядит
```
REVERSE SHELL
~/payload
$
```
## 14. CYBER RANGE

```zsh
PROMPT=$'
%B%F{196}◢ CYBER RANGE ◣%b%f
%F{160}%~%f
%F{88}❯%f '
```

```bash
PS1='\n\
\[\e[1;31m\]◢ CYBER RANGE ◣\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]❯\[\e[0m\] '
```
### Выглядит

```
◢ CYBER RANGE ◣
~/lab
❯
```

## 15. APT TRACKER

```zsh
PROMPT=$'
%B%F{196}APT TRACKER%b%f
%F{240}IOC:%~
%F{160}scan> '
```

```bash
PS1='\n\
\[\e[1;31m\]APT TRACKER\[\e[0m\]
\[\e[38;5;240m\]IOC:\w\[\e[0m\]
\[\e[38;5;160m\]scan>\[\e[0m\] '
```
### Выглядит

```
APT TRACKER
IOC:~/evidence
scan>
```

## 16. VOID TERMINAL

```zsh
PROMPT=$'
%B%F{196}VOID%b%f
%F{240}%~
%F{88}λ%f '
```

```bash
PS1='\n\
\[\e[1;31m\]VOID\[\e[0m\]
\[\e[38;5;240m\]\w\[\e[0m\]
\[\e[38;5;88m\]λ\[\e[0m\] '
```
### Выглядит

```
VOID
~/unknown
λ
```

## 17. DIGITAL FORENSICS

```zsh
PROMPT=$'
%B%F{196}◢ DIGITAL FORENSICS ◣%b%f
%F{240}%~
%F{160}evidence> '
```

```bash
PS1='\n\
\[\e[1;31m\]◢ DIGITAL FORENSICS ◣\[\e[0m\]
\[\e[38;5;240m\]\w\[\e[0m\]
\[\e[38;5;160m\]evidence>\[\e[0m\] '
```
### Выглядит

```
◢ DIGITAL FORENSICS ◣
~/disk-image
evidence>
```
## 18. CYBERPUNK

```zsh
PROMPT=$'
%B%F{196}NEON GRID%b%f
%F{160}%~%f
%F{88}//%f '
```

```bash
PS1='\n\
\[\e[1;31m\]NEON GRID\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]//\[\e[0m\] '
```
### Выглядит

```
NEON GRID
~/matrix
//
```
## 19. FIRMWARE LAB

```zsh
PROMPT=$'
%B%F{196}FIRMWARE LAB%b%f
%F{240}ARM64/ELF
%F{160}%~
%F{196}>>%f '
```

```bash
PS1='\n\
\[\e[1;31m\]FIRMWARE LAB\[\e[0m\]
\[\e[38;5;240m\]ARM64/ELF\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]>>\[\e[0m\] '
```
### Выглядит

```
FIRMWARE LAB
ARM64/ELF
~/router_dump
>>
```
## 20. THE ONE I WOULD USE
```zsh
PROMPT=$'
%B%F{196}◢ REVERSE LAB ◣%b%f
%F{240}%~%f %F{88}[READY]%f
%F{196}▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]◢ REVERSE LAB ◣\[\e[0m\]
\[\e[38;5;240m\]\w\[\e[38;5;88m\] [READY]\[\e[0m\]
\[\e[38;5;196m\]▶\[\e[0m\] '
```
### Выглядит

```
◢ REVERSE LAB ◣
~/crackme [READY]
▶
```

## 21. MALWARE ANALYSIS CONSOLE

```zsh
PROMPT=$'
%B%F{196}╔══ MALWARE ANALYSIS CONSOLE ══╗%b%f
%F{240}║ USER:%n  HOST:%m  PID:%$
%F{160}║ PATH:%~
%F{208}║ MODE: REVERSE ENGINEERING
%F{196}╚══════════════════════════════▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ MALWARE ANALYSIS CONSOLE ══╗\[\e[0m\]
\[\e[38;5;240m\]║ USER:\u HOST:\h PID:$$\[\e[0m\]
\[\e[38;5;160m\]║ PATH:\w\[\e[0m\]
\[\e[38;5;208m\]║ MODE: REVERSE ENGINEERING\[\e[0m\]
\[\e[1;31m\]╚══════════════════════════════▶\[\e[0m\] '
```

### Выглядит
```
╔══ MALWARE ANALYSIS CONSOLE ══╗
║ USER:neo HOST:kali PID:4212
║ PATH:/home/neo/samples
║ MODE: REVERSE ENGINEERING
╚══════════════════════════════▶
```

## 22. IDA PRO STYLE
```zsh
PROMPT=$'
%B%F{208}┌─[ IDA DATABASE ]────────────────%b%f
%F{240}│ FILE : %~ 
│ ARCH : ELF64
│ FUNC : sub_%08>.$$
%F{208}└─ JMP ▶%f '
```
```bash
PS1='\n\
\[\e[1;33m\]┌─[ IDA DATABASE ]────────────────\[\e[0m\]
\[\e[38;5;240m\]│ FILE : \w
│ ARCH : ELF64
│ FUNC : sub_$$\[\e[0m\]
\[\e[1;33m\]└─ JMP ▶\[\e[0m\] '
```

### Выглядит
```
┌─[ IDA DATABASE ]────────────────
│ FILE : ~/crackme
│ ARCH : ELF64
│ FUNC : sub_4012A0
└─ JMP ▶
```

## 23. C2 OPERATOR PANEL
```zsh
PROMPT=$'
%B%F{196}╭─[ C2 OPERATOR ]──────────╮%b%f
%F{240}│ CHANNEL : ENCRYPTED
│ TARGET  : %m
│ USER    : %n
%F{196}╰─────── beacon$ %f'
```
### Выглядит
```
╭─[ C2 OPERATOR ]──────────╮
│ CHANNEL : ENCRYPTED
│ TARGET  : kali
│ USER    : operator
╰─────── beacon$
```
## 24. MEMORY DEBUGGER
```zah
PROMPT=$'
%B%F{196}MEMORY DEBUGGER%b%f
%F{240}RIP  0x%08>.$$
%F{240}RSP  0x7ffffff
%F{160}%~
%F{196}dbg ▶%f '
```

### Выглядит
```
MEMORY DEBUGGER
RIP  0x004012A
RSP  0x7ffffff
~/heap_analysis
dbg ▶
```
## 25. THREAT HUNTING TERMINAL
```zsh
PROMPT=$'
%B%F{196}╔══ THREAT HUNTING ══╗%b%f
%F{240} IOC     : ACTIVE
%F{240} SESSION : %n@%m
%F{160} TARGET  : %~
%F{196}╚════ scan ▶%f '
```

### Выглядит
```
╔══ THREAT HUNTING ══╗
 IOC     : ACTIVE
 SESSION : analyst@kali
 TARGET  : ~/evidence
╚════ scan ▶
```
## 26. FIRMWARE RESEARCH LAB
```zsh
PROMPT=$'
%B%F{196}◢ FIRMWARE LAB ◣%b%f
%F{240}ARCH : ARM64
%F{240}TYPE : BIN
%F{160}%~
%F{196}flash ▶%f '
```

### Выглядит
```
◢ FIRMWARE LAB ◣
ARCH : ARM64
TYPE : BIN
~/router_dump
flash ▶
```
## 27. ZERO DAY LAB
```zsh
PROMPT=$'
%B%F{196}╔══ ZERO DAY LAB ══╗%b%f
%F{240}VULN : UNKNOWN
%F{240}RISK : CRITICAL
%F{160}%~
%F{196}exploit ▶%f '
```

### Выглядит
```
╔══ ZERO DAY LAB ══╗
VULN : UNKNOWN
RISK : CRITICAL
~/poc
exploit ▶
```
## 28. CYBER RANGE TERMINAL
```zsh
PROMPT=$'
%B%F{196}[ CYBER RANGE ]%b%f
%F{240}NODE:%m
%F{160}%~
%F{88}root@lab:%f '
```

### Выглядит
```
[ CYBER RANGE ]
NODE:kali
~/training
root@lab:
```

## 29. GHOST SHELL (очень минималистично)
```zsh
PROMPT=$'
%B%F{196}GHOST://%b%f
%F{160}%~
%F{88}λ%f '
```

### Выглядит
```
GHOST://
~/unknown
λ
```

## 30. REVERSE WORKSTATION
```zsh
PROMPT=$'
%B%F{196}╔══════════════════════════════╗
║  REVERSE ENGINEERING NODE
╠══════════════════════════════╣%b%f
%F{240} USER : %n
 HOST : %m
 DIR  : %~
%F{160} MODE : STATIC ANALYSIS
%F{208} ARCH : ELF64 / x86_64
%F{196}╚══════════════════════════════▶%f '
```

### Выглядит
```
╔══════════════════════════════╗
║  REVERSE ENGINEERING NODE
╠══════════════════════════════╣
 USER : analyst
 HOST : kali
 DIR  : ~/malware
 MODE : STATIC ANALYSIS
 ARCH : ELF64 / x86_64
╚══════════════════════════════▶
```

## 31. SPECTER ANALYSIS NODE

```zsh
PROMPT=$'
%B%F{196}╔══ SPECTER NODE ═══════════╗%b%f
%F{240}║ SESSION : %n@%m
║ TARGET  : %~
║ STATUS  : ANALYZING
%F{196}╚═══════════════════════▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ SPECTER NODE ═══════════╗\[\e[0m\]
\[\e[38;5;240m\]║ SESSION : \u@\h
║ TARGET  : \w
║ STATUS  : ANALYZING\[\e[0m\]
\[\e[1;31m\]╚═══════════════════════▶\[\e[0m\] '
```

### Выглядит
```
╔══ SPECTER NODE ═══════════╗
║ SESSION : analyst@kali
║ TARGET  : ~/samples
║ STATUS  : ANALYZING
╚═══════════════════════▶
```

## 32. NIGHTWATCH SOC
```zsh
PROMPT=$'
%B%F{196}◢ NIGHTWATCH SOC ◣%b%f
%F{240}ALERT : NONE
HOST  : %m
%F{160}%~
%F{196}monitor ▶%f '
```
### Выглядит

```
◢ NIGHTWATCH SOC ◣
ALERT : NONE
HOST  : kali
~/logs
monitor ▶
```

## 33. APOCALYPSE TERMINAL
```zsh
PROMPT=$'
%B%F{196}☠ APOCALYPSE CONSOLE%b%f
%F{240}SYSTEM : COMPROMISED
%F{160}%~
%F{88}root#%f '
```
### Выглядит

```
☠ APOCALYPSE CONSOLE
SYSTEM : COMPROMISED
/root/exploit
root#
```

## 34. BLACK VAULT
```zsh
PROMPT=$'
%B%F{196}╔══ BLACK VAULT ══╗%b%f
%F{240}FILE : %~
HASH : ACTIVE
%F{160}ACCESS GRANTED
%F{196}vault ▶%f '
```
### Выглядит

```
╔══ BLACK VAULT ══╗
FILE : ~/evidence
HASH : ACTIVE
ACCESS GRANTED
vault ▶
```

## 35. RECON TERMINAL

```zsh
PROMPT=$'
%B%F{196}RECON MODULE%b%f
%F{240}SCAN : READY
%F{240}NODE : %m
%F{160}%~
%F{196}scan> %f'
```
### Выглядит

```
RECON MODULE
SCAN : READY
NODE : kali
~/targets
scan>
````
## 36. MALDEV WORKSTATION
```zsh
PROMPT=$'
%B%F{196}╭─ MALDEV WORKSTATION ─╮
%F{240}│ Compiler : GCC
│ Target   : ELF64
│ Folder   : %~
%F{196}╰──────── build ▶%f '
```
### Выглядит

```
╭─ MALDEV WORKSTATION ─╮
│ Compiler : GCC
│ Target   : ELF64
│ Folder   : ~/src
╰──────── build ▶
```
## 37. KERNEL SPACE
```zsh
PROMPT=$'
%B%F{196}KERNEL SPACE%b%f
%F{240}RING : 0
CR3  : 0x%08>.$$
%F{160}%~
%F{196}syscall ▶%f '
```
### Выглядит

```
KERNEL SPACE
RING : 0
CR3  : 0x004012
~/drivers
syscall ▶
```
## 38. BUFFER OVERFLOW LAB
```zsh
PROMPT=$'
%B%F{196}BUFFER LAB%b%f
%F{240}STACK : ████████
RET   : 0x41414141
%F{160}%~
%F{196}pwn ▶%f '
```
### Выглядит

```
BUFFER LAB
STACK : ████████
RET   : 0x41414141
~/pwn
pwn ▶
```
## 39. ROOTKIT LAB
```zsh
PROMPT=$'
%B%F{196}◢ ROOTKIT LAB ◣%b%f
%F{240}KERNEL : ONLINE
HIDDEN : ENABLED
%F{160}%~
%F{196}hide ▶%f '
```
### Выглядит

```
◢ ROOTKIT LAB ◣
KERNEL : ONLINE
HIDDEN : ENABLED
~/module
hide ▶
```
## 40. APT COMMAND CENTER
```zsh
PROMPT=$'
%B%F{196}╔══ APT COMMAND CENTER ══╗%b%f
%F{240}OPERATOR : %n
CHANNEL  : SECURE
TARGET   : %m
%F{160}%~
%F{196}command ▶%f '
```
### Выглядит

```
╔══ APT COMMAND CENTER ══╗
OPERATOR : analyst
CHANNEL  : SECURE
TARGET   : kali
~/ops
command ▶
```
## 41. DIGITAL ARCHAEOLOGY
```zsh
PROMPT=$'
%B%F{196}DIGITAL ARCHAEOLOGY%b%f
%F{240}IMAGE : MOUNTED
%F{240}FORMAT: RAW
%F{160}%~
%F{88}extract ▶%f '
```
### Выглядит

```
DIGITAL ARCHAEOLOGY
IMAGE : MOUNTED
FORMAT: RAW
~/disk
extract ▶
```
## 42. THE MATRIX NODE
```zsh
PROMPT=$'
%B%F{46}WAKE UP NODE%b%f
%F{240}TRACE : ACTIVE
%F{46}%~%f
%F{46}█%f '
```
### Выглядит

```
WAKE UP NODE
TRACE : ACTIVE
~/matrix
█
```
## 43. OBSIDIAN TERMINAL
```zsh
PROMPT=$'
%B%F{196}◢ OBSIDIAN ◣%b%f
%F{240}%n@%m
%F{160}%~
%F{88}◆%f '
```
### Выглядит

```
◢ OBSIDIAN ◣
analyst@kali
~/vault
◆
```
## 44. NEURAL DEBUG
```zsh
PROMPT=$'
%B%F{196}NEURAL DEBUG%b%f
%F{240}MEM : OK
CPU : %~
%F{160}%~
%F{196}train ▶%f '
```
### Выглядит

```
NEURAL DEBUG
MEM : OK
CPU : ~/models
~/work
train ▶
```
## 45. FINAL — BLACKBOX RESEARCH
```zsh
PROMPT=$'
%B%F{196}╔════════ BLACKBOX ════════╗
║ UNKNOWN SAMPLE
║ STATIC ANALYSIS MODE
║ HASH: VERIFIED
║ TARGET: %~
╚═══════════════════════▶%b%f '
```
### Выглядит

```
╔════════ BLACKBOX ════════╗
║ UNKNOWN SAMPLE
║ STATIC ANALYSIS MODE
║ HASH: VERIFIED
║ TARGET: ~/sample
╚═══════════════════════▶
```

## 46. PHANTOM RESEARCH NODE

```zsh
PROMPT=$'
%B%F{196}╔══ PHANTOM NODE ══════════╗%b%f
%F{240}USER : %n
HOST : %m
MODE : STATIC ANALYSIS
%F{160}DIR  : %~
%F{196}╚══════════════════════▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ PHANTOM NODE ══════════╗\[\e[0m\]
\[\e[38;5;240m\]USER : \u
HOST : \h
MODE : STATIC ANALYSIS\[\e[0m\]
\[\e[38;5;160m\]DIR  : \w\[\e[0m\]
\[\e[1;31m\]╚══════════════════════▶\[\e[0m\] '
```

### Выглядит
```
╔══ PHANTOM NODE ══════════╗
USER : analyst
HOST : kali
MODE : STATIC ANALYSIS
DIR  : ~/samples
╚══════════════════════▶
```
## 47. RED CELL LAB
```zsh
PROMPT=$'
%B%F{196}◢ RED CELL LAB ◣%b%f
%F{240}STATUS : ACTIVE
TARGET : %~
%F{160}SESSION:%n
%F{196}redcell ▶%f '
```
### Выглядит

```
◢ RED CELL LAB ◣
STATUS : ACTIVE
TARGET : ~/payloads
SESSION:operator
redcell ▶
```
## 48. SENTINEL MONITOR
```zsh
PROMPT=$'
%B%F{196}[ SENTINEL ]%b%f
%F{240}THREAT : 0
%F{240}EVENTS : MONITORING
%F{160}%~
%F{88}>_%f '
```
### Выглядит

```
[ SENTINEL ]
THREAT : 0
EVENTS : MONITORING
~/logs
>_
```
## 49. BLACK ICE
```zsh
PROMPT=$'
%B%F{196}╔══ BLACK ICE ══╗%b%f
%F{240}FIREWALL : BYPASSED
%F{240}TRACE    : OFF
%F{160}%~
%F{196}access ▶%f '
```
### Выглядит

```
╔══ BLACK ICE ══╗
FIREWALL : BYPASSED
TRACE    : OFF
~/target
access ▶
```
## 50. OPERATOR TERMINAL
```zsh
PROMPT=$'
%B%F{196}OPERATOR CONSOLE%b%f
%F{240}CALLSIGN : %n
%F{240}CHANNEL  : 07
%F{160}%~
%F{196}cmd> %f'
```
### Выглядит

```
OPERATOR CONSOLE
CALLSIGN : analyst
CHANNEL  : 07
~/ops
cmd>
```
## 51. SHELLCODE LAB
```zsh
PROMPT=$'
%B%F{196}╔══ SHELLCODE LAB ══╗%b%f
%F{240}NOP : ACTIVE
%F{240}STACK : READY
%F{160}%~
%F{196}inject ▶%f '
```
### Выглядит

```
╔══ SHELLCODE LAB ══╗
NOP : ACTIVE
STACK : READY
~/exploit
inject ▶
```
## 52. VULNERABILITY RESEARCH
```zsh
PROMPT=$'
%B%F{196}VULN RESEARCH%b%f
%F{240}CVE : UNKNOWN
%F{240}SEVERITY : HIGH
%F{160}%~
%F{196}analyze ▶%f '
```
### Выглядит

```
VULN RESEARCH
CVE : UNKNOWN
SEVERITY : HIGH
~/poc
analyze ▶
```
## 53. MALWARE TRIAGE
```zsh
PROMPT=$'
%B%F{196}◢ MALWARE TRIAGE ◣%b%f
%F{240}HASH : UNKNOWN
%F{240}TYPE : SAMPLE
%F{160}%~
%F{196}queue ▶%f '
```
### Выглядит

```
◢ MALWARE TRIAGE ◣
HASH : UNKNOWN
TYPE : SAMPLE
~/incoming
queue ▶
```
## 53. FORENSIC TERMINAL

```zsh
PROMPT=$'
%B%F{196}FORENSIC TERMINAL%b%f
%F{240}IMAGE : ONLINE
%F{240}CHAIN : VERIFIED
%F{160}%~
%F{88}case#%f '
```
### Выглядит

```
FORENSIC TERMINAL
IMAGE : ONLINE
CHAIN : VERIFIED
~/evidence
case#
```
## 54. DEEP VOID
```zsh
PROMPT=$'
%B%F{196}◢ DEEP VOID ◣%b%f
%F{240}UNKNOWN SPACE
%F{160}%~
%F{88}λ%f '
```
### Выглядит

```
◢ DEEP VOID ◣
UNKNOWN SPACE
~/unknown
λ
```
## 55. ARCHIVE TERMINAL
```zsh
PROMPT=$'
%B%F{196}ARCHIVE://%b%f
%F{240}LEVEL : RESTRICTED
%F{160}%~
%F{196}open ▶%f '
```
### Выглядит

```
ARCHIVE://
LEVEL : RESTRICTED
~/vault
open ▶
```
## 56. HEX TERMINAL
```zsh
PROMPT=$'
%B%F{196}HEX://0x%08>.$$%b%f
%F{240}MEMORY VIEW
%F{160}%~
%F{196}: %f'
```
### Выглядит

```
HEX://0x004012A
MEMORY VIEW
~/dump
:
```
## 57. NEXUS CORE
```zsh
PROMPT=$'
%B%F{196}╔══ NEXUS CORE ══╗%b%f
%F{240}LINK : STABLE
%F{240}NODE : %m
%F{160}%~
%F{196}sync ▶%f '
```
### Выглядит

```
╔══ NEXUS CORE ══╗
LINK : STABLE
NODE : kali
~/core
sync ▶
```

## 58. DARKROOM ANALYSIS
```zsh
PROMPT=$'
%B%F{196}DARKROOM%b%f
%F{240}LIGHT : OFF
%F{240}SAMPLE : LOADED
%F{160}%~
%F{88}▶%f '
```
### Выглядит

```
DARKROOM
LIGHT : OFF
SAMPLE : LOADED
~/sample
▶
```
## 59. ABSOLUTE ZERO ❄️
```zsh
PROMPT=$'
%B%F{196}ABSOLUTE ZERO%b%f
%F{240}TEMPERATURE : LOCKED
%F{240}PROCESS : FROZEN
%F{160}%~
%F{196}resume ▶%f '
```
### Выглядит

```
ABSOLUTE ZERO
TEMPERATURE : LOCKED
PROCESS : FROZEN
~/snapshot
resume ▶
```
## 60.
```zsh
PROMPT=$'
%B%F{196}╔══ MALWARE TRIAGE NODE ══╗%b%f
%F{240}SAMPLE : UNKNOWN
HASH   : PENDING
MODE   : STATIC
%F{160}DIR    : %~
%F{196}analyze ▶%f '
```
### Выглядит

```
╔══ MALWARE TRIAGE NODE ══╗
SAMPLE : UNKNOWN
HASH   : PENDING
MODE   : STATIC
DIR    : ~/incoming
analyze ▶
```

## 61. C2 COMMAND NODE

```zsh
PROMPT=$'
%B%F{196}╔══ C2 COMMAND NODE ══╗%b%f
%F{240}USER:%n HOST:%m
%F{160}DIR:%~
%F{196}╚══ beacon ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ C2 COMMAND NODE ══╗\[\e[0m\]
\[\e[38;5;240m\]USER:\u HOST:\h\[\e[0m\]
\[\e[38;5;160m\]DIR:\w\[\e[0m\]
\[\e[1;31m\]╚══ beacon ▶\[\e[0m\] '
```
### Выглядит

```
╔══ C2 COMMAND NODE ══╗
USER:root HOST:kali
DIR:~/payloads
╚══ beacon ▶
```

## 62. GHOST OPERATOR

```zsh
PROMPT=$'
%B%F{196}GHOST://%b%f
%F{240}SESSION ACTIVE
%F{160}%~
%F{88}λ%f '
```

```bash
PS1='\n\
\[\e[1;31m\]GHOST://\[\e[0m\]
\[\e[38;5;240m\]SESSION ACTIVE\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]λ\[\e[0m\] '
```
### Выглядит

```
GHOST://
SESSION ACTIVE
~/ops
λ
```

## 63. BLACK OPS TERMINAL

```zsh
PROMPT=$'
%B%F{196}◢ BLACK OPS ◣%b%f
%F{240}STATUS: ONLINE
%F{160}%~
%F{196}▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]◢ BLACK OPS ◣\[\e[0m\]
\[\e[38;5;240m\]STATUS: ONLINE\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]▶\[\e[0m\] '
```
### Выглядит

```
◢ BLACK OPS ◣
STATUS: ONLINE
~/operations
▶
```


## 64. ROOTKIT CONSOLE

```zsh
PROMPT=$'
%B%F{196}ROOTKIT CONSOLE%b%f
%F{240}KERNEL : 0
%F{160}%~
%F{196}hide ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]ROOTKIT CONSOLE\[\e[0m\]
\[\e[38;5;240m\]KERNEL : 0\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]hide ▶\[\e[0m\] '
```
### Выглядит

```
ROOTKIT CONSOLE
KERNEL : 0
/root/module
hide ▶
```

## 65. PHANTOM SHELL

```zsh
PROMPT=$'
%B%F{196}PHANTOM SHELL%b%f
%F{240}TRACE : DISABLED
%F{160}%~
%F{88}$_%f '
```

```bash
PS1='\n\
\[\e[1;31m\]PHANTOM SHELL\[\e[0m\]
\[\e[38;5;240m\]TRACE : DISABLED\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]$_\[\e[0m\] '
```
### Выглядит

```
PHANTOM SHELL
TRACE : DISABLED
~/shadow
$_
```

## 66. CYBER WAR ROOM

```zsh
PROMPT=$'
%B%F{196}╔══ CYBER WAR ROOM ══╗%b%f
%F{240}NODE:%m
TARGET:%~
%F{160}MODE:REDTEAM
%F{196}cmd ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ CYBER WAR ROOM ══╗\[\e[0m\]
\[\e[38;5;240m\]NODE:\h
TARGET:\w\[\e[0m\]
\[\e[38;5;160m\]MODE:REDTEAM\[\e[0m\]
\[\e[1;31m\]cmd ▶\[\e[0m\] '
```
### Выглядит

```
╔══ CYBER WAR ROOM ══╗
NODE:kali
TARGET:~/targets
MODE:REDTEAM
cmd ▶
```

## 67. ZERO DAY LAB 

```zsh
PROMPT=$'
%B%F{196}ZERO DAY LAB%b%f
%F{240}CVE: UNKNOWN
%F{240}RISK: CRITICAL
%F{160}%~
%F{196}exploit ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]ZERO DAY LAB\[\e[0m\]
\[\e[38;5;240m\]CVE: UNKNOWN
RISK: CRITICAL\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]exploit ▶\[\e[0m\] '
```
### Выглядит

```
ZERO DAY LAB
CVE: UNKNOWN
RISK: CRITICAL
~/poc
exploit ▶
```
## 68. MATRIX CORE

```zsh
PROMPT=$'
%B%F{46}MATRIX CORE%b%f
%F{240}TRACE ACTIVE
%F{46}%~
█%f '
```

```bash
PS1='\n\
\[\e[1;32m\]MATRIX CORE\[\e[0m\]
\[\e[38;5;240m\]TRACE ACTIVE\[\e[0m\]
\[\e[1;32m\]\w
█\[\e[0m\] '
```
### Выглядит

```
MATRIX CORE
TRACE ACTIVE
~/matrix
█
```
## 69. DARKNET TERMINAL

```zsh
PROMPT=$'
%B%F{196}DARKNET NODE%b%f
%F{240}TOR : ACTIVE
%F{160}%~
%F{88}anonymous@%f '
```

```bash
PS1='\n\
\[\e[1;31m\]DARKNET NODE\[\e[0m\]
\[\e[38;5;240m\]TOR : ACTIVE\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;88m\]anonymous@\[\e[0m\] '
```
### Выглядит

```
DARKNET NODE
TOR : ACTIVE
~/hidden
anonymous@
```
## 70. FINAL — RED TEAM OPERATOR

```zsh
PROMPT=$'
%B%F{196}╔══ RED TEAM OPERATOR ══╗%b%f
%F{240}CALLSIGN : %n
HOST     : %m
%F{160}WORKDIR  : %~
%F{196}╚══════════════▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ RED TEAM OPERATOR ══╗\[\e[0m\]
\[\e[38;5;240m\]CALLSIGN : \u
HOST     : \h\[\e[0m\]
\[\e[38;5;160m\]WORKDIR  : \w\[\e[0m\]
\[\e[1;31m\]╚══════════════▶\[\e[0m\] '
```
### Выглядит

```
╔══ RED TEAM OPERATOR ══╗
CALLSIGN : operator
HOST     : kali
WORKDIR  : ~/engagements
╚══════════════▶
```

## 71. REVERSE ENGINEERING WORKSTATION 

```zsh
PROMPT=$'
%B%F{196}╔════════ REVERSE NODE ════════╗%b%f
%F{240} USER : %n@%m
 ARCH : %m
 MODE : STATIC ANALYSIS
%F{160} DIR  : %~
%F{196}╚══════════════════════════▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔════════ REVERSE NODE ════════╗\[\e[0m\]
\[\e[38;5;240m\] USER : \u@\h
 ARCH : x86_64
 MODE : STATIC ANALYSIS\[\e[0m\]
\[\e[38;5;160m\] DIR  : \w\[\e[0m\]
\[\e[1;31m\]╚══════════════════════════▶\[\e[0m\] '
```
### Выглядит

```
╔════════ REVERSE NODE ════════╗
 USER : analyst@kali
 ARCH : x86_64
 MODE : STATIC ANALYSIS
 DIR  : ~/samples
╚══════════════════════════▶
```

## 72. BLACKBOX MALWARE LAB

```zsh
PROMPT=$'
%B%F{196}╔══ BLACKBOX LAB ══╗%b%f
%F{240} SAMPLE : UNKNOWN
 HASH   : PENDING
 FAMILY : UNKNOWN
%F{160} PATH   : %~
%F{196} ANALYZE ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ BLACKBOX LAB ══╗\[\e[0m\]
\[\e[38;5;240m\] SAMPLE : UNKNOWN
 HASH   : PENDING
 FAMILY : UNKNOWN\[\e[0m\]
\[\e[38;5;160m\] PATH   : \w\[\e[0m\]
\[\e[1;31m\] ANALYZE ▶\[\e[0m\] '
```
### Выглядит

```
╔══ BLACKBOX LAB ══╗
 SAMPLE : UNKNOWN
 HASH   : PENDING
 FAMILY : UNKNOWN
 PATH   : ~/incoming
 ANALYZE ▶
 ```
 
## 73. GHOST OPERATOR HUD

```zsh
PROMPT=$'
%B%F{196}╭─ GHOST OPERATOR ─╮%b%f
%F{240} STATUS : ONLINE
 TRACE  : HIDDEN
%F{160} LOC    : %~
%F{196}╰─▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╭─ GHOST OPERATOR ─╮\[\e[0m\]
\[\e[38;5;240m\] STATUS : ONLINE
 TRACE  : HIDDEN\[\e[0m\]
\[\e[38;5;160m\] LOC    : \w\[\e[0m\]
\[\e[1;31m\]╰─▶\[\e[0m\] '
```
### Выглядит

```
╭─ GHOST OPERATOR ─╮
 STATUS : ONLINE
 TRACE  : HIDDEN
 LOC    : ~/ops
╰─▶
```
## 74. KERNEL DEBUGGER

```zsh
PROMPT=$'
%B%F{196}KERNEL DEBUGGER%b%f
%F{240} RING : 0
 CR3  : 0x004000
 RIP  : 0x%08>.$$
%F{160}%~
%F{196}dbg ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]KERNEL DEBUGGER\[\e[0m\]
\[\e[38;5;240m\] RING : 0
 CR3  : 0x004000
 RIP  : 0x$$\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]dbg ▶\[\e[0m\] '
```
### Выглядит

```
KERNEL DEBUGGER
 RING : 0
 CR3  : 0x004000
 RIP  : 0x4812
~/kernel
dbg ▶
```
## 75. SOC NIGHT WATCH

```zsh
PROMPT=$'
%B%F{196}╔══ NIGHT WATCH SOC ══╗%b%f
%F{240} ALERTS : 0
 EVENTS : LIVE
 NODE   : %m
%F{160} DIR    : %~
%F{196}monitor ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ NIGHT WATCH SOC ══╗\[\e[0m\]
\[\e[38;5;240m\] ALERTS : 0
 EVENTS : LIVE
 NODE   : \h\[\e[0m\]
\[\e[38;5;160m\] DIR    : \w\[\e[0m\]
\[\e[1;31m\]monitor ▶\[\e[0m\] '
```
### Выглядит

```
╔══ NIGHT WATCH SOC ══╗
 ALERTS : 0
 EVENTS : LIVE
 NODE   : kali
 DIR    : ~/logs
monitor ▶
```
## 76. ZERO DAY RESEARCH

```zsh
PROMPT=$'
%B%F{196}╔══ ZERO DAY LAB ══╗%b%f
%F{240} CVE    : UNKNOWN
 VECTOR : OPEN
 IMPACT : HIGH
%F{160} %~
%F{196}exploit ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔══ ZERO DAY LAB ══╗\[\e[0m\]
\[\e[38;5;240m\] CVE    : UNKNOWN
 VECTOR : OPEN
 IMPACT : HIGH\[\e[0m\]
\[\e[38;5;160m\] \w\[\e[0m\]
\[\e[1;31m\]exploit ▶\[\e[0m\] '
```
### Выглядит

```
╔══ ZERO DAY LAB ══╗
 CVE    : UNKNOWN
 VECTOR : OPEN
 IMPACT : HIGH
 ~/poc
 exploit ▶
 ```
## 77. CYBERPUNK TERMINAL

```zsh
PROMPT=$'
%B%F{46}╔══ NEON GRID ══╗%b%f
%F{240} CONNECTION : ACTIVE
%F{46} NODE : %~
█%f '
```

```bash
PS1='\n\
\[\e[1;32m\]╔══ NEON GRID ══╗\[\e[0m\]
\[\e[38;5;240m\] CONNECTION : ACTIVE\[\e[0m\]
\[\e[1;32m\] NODE : \w
█\[\e[0m\] '
```
### Выглядит

```
╔══ NEON GRID ══╗
 CONNECTION : ACTIVE
 NODE : ~/matrix
█
```
## 78. ELF ANALYSIS TERMINAL

```zsh
PROMPT=$'
%B%F{196}ELF ANALYZER%b%f
%F{240} FORMAT : ELF64
 ENTRY  : 0x401000
%F{160}%~
%F{196}load ▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]ELF ANALYZER\[\e[0m\]
\[\e[38;5;240m\] FORMAT : ELF64
 ENTRY  : 0x401000\[\e[0m\]
\[\e[38;5;160m\]\w\[\e[0m\]
\[\e[38;5;196m\]load ▶\[\e[0m\] '
```
### Выглядит

```
ELF ANALYZER
 FORMAT : ELF64
 ENTRY  : 0x401000
 ~/bin
 load ▶
 ```
## 79. FINAL FORM — OPERATOR STATION

```zsh
PROMPT=$'
%B%F{196}╔════════════════════════╗
║  OPERATOR STATION v1.0
╠════════════════════════╣%b%f
%F{240} USER : %n
 HOST : %m
 MODE : RED TEAM
%F{160} PATH : %~
%F{208} ARCH : x86_64
%F{196}╚════════════════════════▶%f '
```

```bash
PS1='\n\
\[\e[1;31m\]╔════════════════════════╗
║  OPERATOR STATION v1.0
╠════════════════════════╣\[\e[0m\]
\[\e[38;5;240m\] USER : \u
 HOST : \h
 MODE : RED TEAM\[\e[0m\]
\[\e[38;5;160m\] PATH : \w\[\e[0m\]
\[\e[38;5;208m\] ARCH : x86_64\[\e[0m\]
\[\e[1;31m\]╚════════════════════════▶\[\e[0m\] '
```
### Выглядит

```
╔════════════════════════╗
║  OPERATOR STATION v1.0
╠════════════════════════╣
 USER : analyst
 HOST : kali
 MODE : RED TEAM
 PATH : ~/engagement
 ARCH : x86_64
╚════════════════════════▶
```
