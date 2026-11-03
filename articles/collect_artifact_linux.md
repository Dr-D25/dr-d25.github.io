# Linux Artifact Collector

Скрипт на Python 3 для сбора криминалистических артефактов (forensic artifacts) с Linux-системы. Собирает данные о системе, процессах, сети, пользователях, персистентности, ядре, безопасности и многом другом, структурирует результат и сохраняет его в JSON.

Скрипт предназначен для задач incident response, threat hunting, аудита и цифровой криминалистики. Не изменяет систему — только читает данные.


```python
#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import glob
import datetime
import re
import argparse
import hashlib
import pwd
import grp
import collections
from typing import Any, Dict, List, Optional


def clean_string(s):
    if not isinstance(s, str):
        return s
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)


def run_command(cmd, timeout=10):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors='replace'
        )
        if result.stdout:
            return clean_string(result.stdout.strip()) or None
        return None
    except Exception:
        return None


def run_command_full(cmd, timeout=10):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors='replace'
        )
        return {
            'stdout': clean_string(result.stdout) if result.stdout else None,
            'stderr': clean_string(result.stderr) if result.stderr else None,
            'returncode': result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {'stdout': None, 'stderr': 'timeout', 'returncode': -1}
    except Exception as e:
        return {'stdout': None, 'stderr': str(e), 'returncode': -1}


def read_file_lines(path, max_lines=100):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            if max_lines:
                lines = list(collections.deque(f, maxlen=max_lines))
            else:
                lines = f.readlines()
        return [clean_string(line.rstrip('\n')) for line in lines]
    except Exception:
        return None


def read_file_raw(path, max_lines=100):
    lines = read_file_lines(path, max_lines)
    if lines is None:
        return None
    return '\n'.join(lines)


def list_directory(path, max_items=100, include_hidden=True):
    try:
        items = []
        with os.scandir(path) as it:
            for entry in it:
                if not include_hidden and entry.name.startswith('.'):
                    continue
                try:
                    stat = entry.stat(follow_symlinks=False)
                    items.append({
                        'name': entry.name,
                        'is_dir': entry.is_dir(follow_symlinks=False),
                        'is_symlink': entry.is_symlink(),
                        'size': stat.st_size if entry.is_file(follow_symlinks=False) else None,
                        'mode': oct(stat.st_mode),
                        'uid': stat.st_uid,
                        'gid': stat.st_gid,
                        'mtime': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })
                except Exception:
                    pass
        items.sort(key=lambda x: x.get('mtime') or '', reverse=True)
        return items[:max_items]
    except Exception:
        return None


def get_user_homes():
    homes = set()
    try:
        for entry in pwd.getpwall():
            home = entry.pw_dir
            if home and os.path.isdir(home):
                homes.add(home)
    except Exception:
        pass
    return sorted(homes)


def get_file_metadata(path):
    if not os.path.exists(path):
        return None
    try:
        st = os.stat(path)
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            group = str(st.st_gid)
        return {
            'size': st.st_size,
            'mode': oct(st.st_mode),
            'uid': st.st_uid,
            'gid': st.st_gid,
            'owner': owner,
            'group': group,
            'atime': datetime.datetime.fromtimestamp(st.st_atime).isoformat(),
            'mtime': datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
            'ctime': datetime.datetime.fromtimestamp(st.st_ctime).isoformat(),
        }
    except Exception:
        return None


def file_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def parse_ss_tupln(output):
    if not output:
        return []
    result = []
    header_found = False
    for line in output.split('\n'):
        if not line.strip():
            continue
        if 'Netid' in line and 'State' in line:
            header_found = True
            continue
        if not header_found:
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        result.append({
            'netid': parts[0],
            'state': parts[1],
            'recv_q': parts[2],
            'send_q': parts[3],
            'local_address': parts[4],
            'peer_address': parts[5],
            'process': clean_string(parts[6]) if len(parts) > 6 else None,
        })
    return result


def parse_netstat_plunto(output):
    if not output:
        return []
    result = []
    header_found = False
    for line in output.split('\n'):
        if not line.strip():
            continue
        if 'Proto' in line and 'Recv-Q' in line:
            header_found = True
            continue
        if not header_found:
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        result.append({
            'proto': parts[0],
            'recv_q': parts[1],
            'send_q': parts[2],
            'local_address': parts[3],
            'foreign_address': parts[4],
            'state': parts[5],
            'pid_program': clean_string(parts[6]) if len(parts) > 6 else None,
        })
    return result


def parse_last(output):
    if not output:
        return []
    result = []
    iso_re = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)')
    dur_re = re.compile(r'\((\d+:\d+)\)')
    for line in output.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('wtmp') or stripped.startswith('btmp'):
            continue
        parts = stripped.split()
        timestamps = iso_re.findall(stripped)
        dur = dur_re.search(stripped)
        result.append({
            'user': parts[0] if parts else None,
            'terminal': parts[1] if len(parts) > 1 else None,
            'host': parts[2] if len(parts) > 2 else None,
            'timestamps': timestamps,
            'duration': dur.group(1) if dur else None,
            'raw': clean_string(stripped),
        })
    return result


def parse_mounts(output):
    if not output:
        return []
    result = []
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        result.append({
            'device': parts[0],
            'mountpoint': parts[1],
            'fstype': parts[2],
            'options': parts[3],
            'dump': parts[4],
            'pass': parts[5],
        })
    return result


def parse_passwd(output):
    if not output:
        return []
    result = []
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split(':')
        if len(parts) < 7:
            continue
        result.append({
            'username': parts[0],
            'password': parts[1],
            'uid': int(parts[2]) if parts[2].isdigit() else parts[2],
            'gid': int(parts[3]) if parts[3].isdigit() else parts[3],
            'gecos': parts[4],
            'home': parts[5],
            'shell': parts[6],
        })
    return result


def parse_group(output):
    if not output:
        return []
    result = []
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split(':')
        if len(parts) < 4:
            continue
        result.append({
            'groupname': parts[0],
            'password': parts[1],
            'gid': int(parts[2]) if parts[2].isdigit() else parts[2],
            'members': parts[3].split(',') if parts[3] else [],
        })
    return result


def parse_crontab(content, has_user=False):
    if not content:
        return []
    result = []
    for line in content.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        first = stripped.split(None, 1)[0]
        if not stripped.startswith('@') and '=' in first:
            continue
        if stripped.startswith('@'):
            if has_user:
                parts = stripped.split(None, 2)
                if len(parts) < 3:
                    continue
                schedule, user, command = parts[0], parts[1], parts[2]
            else:
                parts = stripped.split(None, 1)
                if len(parts) < 2:
                    continue
                schedule, user, command = parts[0], None, parts[1]
        else:
            if has_user:
                parts = stripped.split(None, 6)
                if len(parts) < 7:
                    continue
                schedule = ' '.join(parts[:5])
                user = parts[5]
                command = parts[6]
            else:
                parts = stripped.split(None, 5)
                if len(parts) < 6:
                    continue
                schedule = ' '.join(parts[:5])
                user = None
                command = parts[5]
        result.append({
            'schedule': schedule,
            'user': user,
            'command': clean_string(command),
        })
    return result


def collect_system_info():
    info = {}
    uname = os.uname()
    info['hostname'] = uname.nodename
    info['kernel'] = uname.release
    info['architecture'] = uname.machine
    info['sysname'] = uname.sysname
    info['version'] = uname.version
    info['proc_version'] = read_file_lines('/proc/version')
    for f in ['/etc/os-release', '/etc/lsb-release', '/etc/redhat-release']:
        lines = read_file_lines(f)
        if lines:
            info['os_release'] = lines
            info['os_release_path'] = f
            break
    try:
        if os.path.islink('/etc/localtime'):
            info['localtime'] = clean_string(os.readlink('/etc/localtime'))
    except Exception:
        info['localtime'] = None
    info['uptime'] = read_file_raw('/proc/uptime')
    info['uptime_human'] = run_command('uptime -p 2>/dev/null')
    info['date_utc'] = run_command('date -u +"%Y-%m-%dT%H:%M:%SZ"')
    info['timedatectl'] = run_command('timedatectl 2>/dev/null')
    info['hostnamectl'] = run_command('hostnamectl 2>/dev/null')
    btime = None
    for line in (read_file_lines('/proc/stat') or []):
        if line.startswith('btime'):
            btime = line
            break
    info['boot_time'] = btime
    return info


def collect_processes():
    proc_info = {}
    proc_info['raw'] = run_command('ps auxwf')

    structured = []
    ps_output = run_command('ps -eo pid,ppid,user,pcpu,pmem,vsz,rss,tty,stat,start,time,args --no-headers')
    if ps_output:
        for line in ps_output.split('\n'):
            if not line.strip():
                continue
            parts = line.split(None, 11)
            if len(parts) < 12:
                continue
            try:
                structured.append({
                    'pid': int(parts[0]),
                    'ppid': int(parts[1]),
                    'user': parts[2],
                    'cpu': float(parts[3]) if parts[3] != '-' else None,
                    'mem': float(parts[4]) if parts[4] != '-' else None,
                    'vsz': int(parts[5]) if parts[5].isdigit() else None,
                    'rss': int(parts[6]) if parts[6].isdigit() else None,
                    'tty': parts[7] if parts[7] != '?' else None,
                    'stat': parts[8],
                    'start': parts[9],
                    'time': parts[10],
                    'command': clean_string(parts[11]),
                })
            except (ValueError, IndexError):
                continue
    proc_info['structured'] = structured

    cmdlines = {}
    try:
        for d in glob.glob('/proc/[0-9]*'):
            try:
                pid = int(os.path.basename(d))
                with open(f'/proc/{pid}/cmdline', 'rb') as f:
                    data = f.read().replace(b'\0', b' ').decode('utf-8', errors='replace')
                cmdlines[str(pid)] = clean_string(data.strip()) or None
            except Exception:
                continue
    except Exception:
        pass
    proc_info['cmdline'] = cmdlines

    suspicious = []
    suspicious_paths = ('/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/', '/var/run/')
    for pid_str, cmd in cmdlines.items():
        if not cmd:
            continue
        tokens = cmd.split()
        if not tokens:
            continue
        first_token = tokens[0]
        is_suspicious = False
        reasons = []
        if any(first_token.startswith(p) for p in suspicious_paths):
            is_suspicious = True
            reasons.append('binary_in_tmp')
        try:
            exe_link = os.readlink(f'/proc/{pid_str}/exe')
            if ' (deleted)' in exe_link:
                is_suspicious = True
                reasons.append('deleted_exe')
            elif any(exe_link.startswith(p) for p in suspicious_paths):
                is_suspicious = True
                reasons.append('exe_in_tmp')
        except Exception:
            pass
        if is_suspicious:
            suspicious.append({
                'pid': int(pid_str),
                'cmdline': cmd,
                'reasons': reasons,
            })
    proc_info['suspicious'] = suspicious

    kernel_threads = []
    for pid_str, cmd in cmdlines.items():
        if cmd and cmd.startswith('[') and cmd.endswith(']'):
            try:
                with open(f'/proc/{pid_str}/status', 'r') as f:
                    status = f.read()
                if 'Name:\t' in status and 'kthreadd' not in status and 'kworker' in status.lower():
                    kernel_threads.append({'pid': int(pid_str), 'cmdline': cmd})
            except Exception:
                continue
    proc_info['kernel_thread_sample'] = kernel_threads[:20]
    return proc_info


def collect_network():
    net = {}
    raw_ss = run_command('ss -tupln')
    net['ss'] = {'raw': raw_ss, 'structured': parse_ss_tupln(raw_ss)}
    raw_netstat = run_command('netstat -plunto')
    net['netstat'] = {'raw': raw_netstat, 'structured': parse_netstat_plunto(raw_netstat)}
    net['established'] = run_command('ss -tunap state established 2>/dev/null')
    net['listening'] = run_command('ss -tulnp 2>/dev/null')

    configs = {}
    configs['interfaces'] = read_file_lines('/etc/network/interfaces')
    lease_files = glob.glob('/var/lib/NetworkManager/*.lease') + glob.glob('/var/lib/dhcp/*.lease')
    leases = {}
    for f in lease_files[:5]:
        leases[f] = read_file_lines(f, max_lines=50)
    configs['leases'] = leases
    ifcfg = {}
    for f in glob.glob('/etc/sysconfig/network-scripts/ifcfg-*')[:10]:
        ifcfg[f] = read_file_lines(f)
    configs['ifcfg'] = ifcfg
    configs['iptables'] = run_command_full('iptables -L -n -v 2>/dev/null')
    configs['ip6tables'] = run_command_full('ip6tables -L -n -v 2>/dev/null')
    configs['nftables'] = run_command_full('nft list ruleset 2>/dev/null')
    configs['ufw'] = run_command_full('ufw status verbose 2>/dev/null')
    configs['firewalld'] = run_command_full('firewall-cmd --list-all 2>/dev/null')
    configs['sysconfig_iptables'] = read_file_lines('/etc/sysconfig/iptables')
    configs['sysctl_net'] = {}
    for f in ['/etc/sysctl.conf'] + glob.glob('/etc/sysctl.d/*.conf'):
        if os.path.exists(f):
            configs['sysctl_net'][f] = read_file_lines(f, max_lines=100)
    configs['ip_forward'] = read_file_raw('/proc/sys/net/ipv4/ip_forward')
    net['configs'] = configs
    return net


def collect_ip_route_arp():
    return {
        'ip_addr': run_command('ip addr 2>/dev/null'),
        'ip_route': run_command('ip route 2>/dev/null'),
        'ip_neigh': run_command('ip neigh 2>/dev/null'),
        'ip_link': run_command('ip link 2>/dev/null'),
        'arp': run_command('arp -an 2>/dev/null'),
        'proc_net_arp': read_file_lines('/proc/net/arp'),
        'proc_net_route': read_file_lines('/proc/net/route'),
        'proc_net_dev': read_file_lines('/proc/net/dev'),
        'proc_net_tcp': read_file_lines('/proc/net/tcp'),
        'proc_net_udp': read_file_lines('/proc/net/udp'),
    }


def collect_last_logins():
    raw_last = run_command('last --time-format iso -Faiwx 2>/dev/null')
    return {'raw': raw_last, 'structured': parse_last(raw_last)}


def collect_logged_users():
    raw_lastb = run_command('lastb --time-format iso -Faiwx 2>/dev/null')
    return {
        'who': run_command('who 2>/dev/null'),
        'w': run_command('w 2>/dev/null'),
        'users': run_command('users 2>/dev/null'),
        'lastb_raw': raw_lastb,
        'lastb_structured': parse_last(raw_lastb),
        'faillog': run_command('faillog -a 2>/dev/null'),
    }


def collect_logs():
    log_files = [
        '/var/log/auth.log', '/var/log/secure', '/var/log/lastlog',
        '/var/log/btmp', '/var/log/wtmp', '/var/log/cron',
        '/var/log/dpkg.log', '/var/log/apt/history.log',
        '/var/log/audit/audit.log', '/var/log/syslog', '/var/log/messages',
        '/var/log/kern.log', '/var/log/daemon.log', '/var/log/debug',
        '/var/log/user.log', '/var/log/maillog', '/var/log/mail.log',
        '/var/log/yum.log', '/var/log/dnf.log', '/var/log/pacman.log',
    ]
    binary_logs = {'/var/log/lastlog', '/var/log/btmp', '/var/log/wtmp'}
    logs = {}
    for f in log_files:
        if not os.path.exists(f):
            logs[f] = None
            continue
        if f in binary_logs:
            logs[f] = {'binary': True, 'metadata': get_file_metadata(f)}
        else:
            logs[f] = read_file_lines(f, max_lines=50)
    logs['journal_present'] = os.path.isdir('/var/log/journal')
    logs['journal_dirs'] = []
    for d in ['/var/log/journal', '/run/log/journal']:
        if os.path.isdir(d):
            logs['journal_dirs'].append(d)
    return logs


def collect_command_history():
    history = {}
    names = [
        '.bash_history', '.zsh_history', '.sh_history', '.ksh_history',
        '.csh_history', '.tcsh_history', '.ash_history',
        '.python_history', '.node_repl_history', '.irb_history',
        '.pry_history', '.mysql_history', '.psql_history',
        '.sqlite_history', '.viminfo', '.lesshst', '.wget-hsts',
        '.perldb', '.rediscli_history', '.gdb_history', '.history',
    ]
    for home in get_user_homes():
        user = os.path.basename(home)
        hist = {}
        for hf in names:
            path = os.path.join(home, hf)
            if os.path.exists(path):
                hist[hf] = {
                    'content': read_file_lines(path, max_lines=50),
                    'metadata': get_file_metadata(path),
                }
        for f in glob.glob(os.path.join(home, '.*_history')) + glob.glob(os.path.join(home, '.*history')):
            base = os.path.basename(f)
            if base in names:
                continue
            if os.path.isfile(f):
                hist[base] = {
                    'content': read_file_lines(f, max_lines=50),
                    'metadata': get_file_metadata(f),
                }
        if hist:
            history[user] = hist
    return history


def collect_mounts():
    raw_proc = read_file_raw('/proc/mounts')
    raw_etc = read_file_raw('/etc/mtab')
    return {
        'proc_mounts': {'raw': raw_proc, 'structured': parse_mounts(raw_proc)},
        'etc_mtab': {'raw': raw_etc, 'structured': parse_mounts(raw_etc)},
        'mount_output': run_command('mount 2>/dev/null'),
        'fstab': read_file_lines('/etc/fstab'),
        'fstab_d': {f: read_file_lines(f) for f in glob.glob('/etc/fstab.d/*')},
        'findmnt': run_command('findmnt -A 2>/dev/null'),
    }


def collect_user_accounts():
    users = {}
    passwd_raw = read_file_raw('/etc/passwd')
    users['passwd'] = {'raw': passwd_raw, 'structured': parse_passwd(passwd_raw)}
    users['shadow'] = {
        'content': read_file_lines('/etc/shadow'),
        'metadata': get_file_metadata('/etc/shadow'),
    }
    group_raw = read_file_raw('/etc/group')
    users['group'] = {'raw': group_raw, 'structured': parse_group(group_raw)}
    users['gshadow'] = read_file_lines('/etc/gshadow')
    users['sudoers'] = {
        'content': read_file_lines('/etc/sudoers'),
        'metadata': get_file_metadata('/etc/sudoers'),
    }
    users['sudoers_d'] = {}
    for f in glob.glob('/etc/sudoers.d/*'):
        users['sudoers_d'][f] = {
            'content': read_file_lines(f),
            'metadata': get_file_metadata(f),
        }
    users['profile'] = read_file_lines('/etc/profile')
    users['profile_d'] = {f: read_file_lines(f) for f in glob.glob('/etc/profile.d/*')}
    users['bash_bashrc'] = read_file_lines('/etc/bash.bashrc')
    users['bashrc'] = read_file_lines('/etc/bashrc')
    users['environment'] = read_file_lines('/etc/environment')
    users['securetty'] = read_file_lines('/etc/securetty')
    users['login_defs'] = read_file_lines('/etc/login.defs')
    users['hosts_allow'] = read_file_lines('/etc/hosts.allow')
    users['hosts_deny'] = read_file_lines('/etc/hosts.deny')
    return users


def collect_user_dotfiles():
    dotfiles = {}
    names = [
        '.bashrc', '.bash_profile', '.bash_login', '.bash_logout',
        '.profile', '.zshrc', '.zprofile', '.zshenv', '.zlogin', '.zlogout',
        '.kshrc', '.cshrc', '.tcshrc', '.vimrc', '.inputrc', '.selected_editor',
        '.xsession', '.xinitrc', '.xprofile', '.tmux.conf', '.screenrc',
    ]
    for home in get_user_homes():
        user = os.path.basename(home)
        user_dots = {}
        for name in names:
            p = os.path.join(home, name)
            if os.path.exists(p):
                user_dots[name] = {
                    'content': read_file_lines(p, max_lines=300),
                    'metadata': get_file_metadata(p),
                }
        if user_dots:
            dotfiles[user] = user_dots
    return dotfiles


def collect_ssh_artifacts():
    users_data = {}
    global_data = {}
    for home in get_user_homes():
        user = os.path.basename(home)
        ssh_dir = os.path.join(home, '.ssh')
        if not os.path.isdir(ssh_dir):
            continue
        user_data = {'dir_metadata': get_file_metadata(ssh_dir)}
        user_data['dir_listing'] = list_directory(ssh_dir, max_items=100)
        for fname, limit in [
            ('authorized_keys', 200),
            ('known_hosts', 100),
            ('config', 100),
            ('authorized_keys2', 50),
            ('environment', 20),
        ]:
            p = os.path.join(ssh_dir, fname)
            if os.path.exists(p):
                user_data[fname] = {
                    'content': read_file_lines(p, max_lines=limit),
                    'metadata': get_file_metadata(p),
                }
        for key_name in ('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa1'):
            key_path = os.path.join(ssh_dir, key_name)
            if os.path.exists(key_path):
                user_data[f'{key_name}_metadata'] = get_file_metadata(key_path)
                pub_path = key_path + '.pub'
                if os.path.exists(pub_path):
                    user_data[f'{key_name}_pub'] = read_file_lines(pub_path, max_lines=10)
        if len(user_data) > 1:
            users_data[user] = user_data

    for f in ('/etc/ssh/sshd_config', '/etc/ssh/ssh_config'):
        if os.path.exists(f):
            global_data[f] = {
                'content': read_file_lines(f, max_lines=300),
                'metadata': get_file_metadata(f),
            }
    sshd_d = {}
    for f in glob.glob('/etc/ssh/sshd_config.d/*'):
        sshd_d[f] = {'content': read_file_lines(f), 'metadata': get_file_metadata(f)}
    if sshd_d:
        global_data['sshd_config_d'] = sshd_d
    hosts_keys = {}
    for f in glob.glob('/etc/ssh/ssh_host_*_key.pub'):
        hosts_keys[f] = read_file_lines(f, max_lines=10)
    if hosts_keys:
        global_data['host_keys'] = hosts_keys
    return {'users': users_data, 'global': global_data}


def collect_tool_configs():
    configs = {}
    rel_paths = [
        '.netrc', '.gitconfig', '.git-credentials', '.npmrc', '.pypirc',
        '.aws/credentials', '.aws/config', '.azure/azureProfile.json',
        '.config/gcloud/credentials.db', '.kube/config',
        '.docker/config.json', '.wgetrc', '.curlrc', '.pgpass', '.my.cnf',
        '.my.cnf', '.mongorc.js', '.eslintrc', '.editorconfig',
        '.config/gh/hosts.yml', '.config/git/config',
    ]
    for home in get_user_homes():
        user = os.path.basename(home)
        user_configs = {}
        for rel in rel_paths:
            p = os.path.join(home, rel)
            if not os.path.exists(p):
                continue
            try:
                st = os.stat(p)
                entry = {'metadata': get_file_metadata(p)}
                if os.path.isfile(p) and st.st_size < 1024 * 1024:
                    entry['content'] = read_file_lines(p, max_lines=200)
                user_configs[rel] = entry
            except Exception:
                user_configs[rel] = None
        if user_configs:
            configs[user] = user_configs
    return configs


def collect_suspicious_dirs():
    dirs = ['/tmp', '/var/tmp', '/dev/shm', '/var/run', '/var/spool', '/run', '/run/user']
    result = {}
    for d in dirs:
        if not os.path.isdir(d):
            result[d] = None
            continue
        listing = list_directory(d, max_items=100)
        hidden = None
        try:
            hidden = [x for x in (listing or []) if x['name'].startswith('.')]
        except Exception:
            pass
        result[d] = {'listing': listing, 'hidden': hidden}
    return result


def collect_file_metadata():
    important_files = [
        '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
        '/etc/sudoers', '/etc/network/interfaces', '/etc/resolv.conf',
        '/etc/hosts', '/etc/fstab', '/etc/crontab', '/etc/ssh/sshd_config',
        '/etc/ssh/ssh_config', '/etc/apt/sources.list',
        '/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/environment',
        '/etc/profile', '/etc/bash.bashrc', '/etc/rc.local',
        '/etc/pam.d/su', '/etc/pam.d/sshd', '/etc/pam.d/login',
        '/root/.bashrc', '/root/.profile', '/root/.ssh/authorized_keys',
        '/etc/systemd/system', '/etc/selinux/config',
    ]
    metadata = {}
    for f in important_files:
        metadata[f] = get_file_metadata(f)
    return metadata


def collect_file_hashes():
    binaries = [
        '/bin/ls', '/bin/ps', '/usr/bin/ls', '/usr/bin/ps', '/usr/bin/top',
        '/usr/bin/ss', '/bin/ss', '/usr/bin/netstat', '/bin/netstat',
        '/usr/sbin/sshd', '/usr/bin/sudo', '/bin/su', '/usr/bin/su',
        '/usr/bin/ssh', '/bin/login', '/usr/bin/passwd', '/usr/bin/crontab',
        '/usr/bin/find', '/usr/bin/grep', '/usr/bin/awk', '/bin/bash',
        '/bin/sh', '/usr/bin/python3', '/usr/bin/perl',
        '/usr/bin/systemctl', '/sbin/init', '/usr/bin/wget', '/usr/bin/curl',
        '/usr/bin/docker', '/usr/bin/kill', '/bin/kill',
    ]
    result = {}
    for b in binaries:
        if not os.path.exists(b):
            result[b] = None
            continue
        try:
            st = os.stat(b)
            result[b] = {
                'sha256': file_sha256(b),
                'size': st.st_size,
                'mtime': datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
            }
        except Exception:
            result[b] = None
    return result


def collect_writable_path_dirs():
    path_env = os.environ.get('PATH', '')
    dirs = [d for d in path_env.split(':') if d]
    result = []
    for d in dirs:
        try:
            if os.path.isdir(d):
                result.append({'path': d, 'writable': os.access(d, os.W_OK)})
            else:
                result.append({'path': d, 'exists': False})
        except Exception:
            continue
    return result


def collect_lsof_version():
    return run_command('lsof -v 2>/dev/null | head -10')


def collect_cron_jobs():
    cron = {}
    crontab_raw = read_file_raw('/etc/crontab')
    cron['crontab'] = {
        'raw': crontab_raw,
        'structured': parse_crontab(crontab_raw, has_user=True),
    }
    cron_d = {}
    for f in glob.glob('/etc/cron.d/*'):
        content_raw = read_file_raw(f)
        cron_d[f] = {
            'raw': content_raw,
            'structured': parse_crontab(content_raw, has_user=True),
            'metadata': get_file_metadata(f),
        }
    cron['cron_d'] = cron_d

    user_crons = {}
    for d in ('/var/spool/cron', '/var/spool/cron/crontabs'):
        if not os.path.isdir(d):
            continue
        for f in glob.glob(os.path.join(d, '*')):
            if not os.path.isfile(f):
                continue
            content_raw = read_file_raw(f, 500)
            user_crons[f] = {
                'raw': content_raw,
                'structured': parse_crontab(content_raw, has_user=False),
                'metadata': get_file_metadata(f),
            }
    cron['user_crontabs'] = user_crons
    return cron


def collect_persistence():
    data = {}
    for f in ['/etc/rc.local', '/etc/rc.d/rc.local', '/etc/init.d/rc.local']:
        if os.path.exists(f):
            data[f] = {'content': read_file_lines(f), 'metadata': get_file_metadata(f)}
    data['cron_periodic'] = {}
    for d in ('/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly'):
        if os.path.isdir(d):
            data['cron_periodic'][d] = list_directory(d, max_items=100)
    data['init_d'] = list_directory('/etc/init.d', max_items=200) if os.path.isdir('/etc/init.d') else None
    data['rc_dirs'] = {}
    for d in sorted(glob.glob('/etc/rc*.d')):
        data['rc_dirs'][d] = list_directory(d, max_items=100)
    data['motd'] = {}
    for f in ('/etc/motd', '/etc/issue', '/etc/issue.net'):
        if os.path.exists(f):
            data['motd'][f] = {'content': read_file_lines(f), 'metadata': get_file_metadata(f)}
    data['update_motd_d'] = list_directory('/etc/update-motd.d', max_items=50) if os.path.isdir('/etc/update-motd.d') else None
    data['ld_so_conf'] = read_file_lines('/etc/ld.so.conf')
    data['ld_so_conf_d'] = {f: read_file_lines(f) for f in glob.glob('/etc/ld.so.conf.d/*')}
    data['skel'] = list_directory('/etc/skel', max_items=100) if os.path.isdir('/etc/skel') else None
    return data


def collect_systemd():
    data = {}
    data['is_systemd'] = os.path.isdir('/run/systemd/system')
    data['list_units'] = run_command('systemctl list-units --all --no-pager --no-legend 2>/dev/null')
    data['list_unit_files'] = run_command('systemctl list-unit-files --no-pager --no-legend 2>/dev/null')
    raw_enabled = run_command('systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null')
    data['enabled_services'] = raw_enabled
    enabled_names = []
    if raw_enabled:
        for line in raw_enabled.split('\n'):
            parts = line.split()
            if parts:
                enabled_names.append(parts[0])
    data['enabled_service_names'] = enabled_names
    data['timers'] = run_command('systemctl list-timers --all --no-pager --no-legend 2>/dev/null')
    unit_dirs = {}
    for d in ('/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system'):
        if os.path.isdir(d):
            unit_dirs[d] = list_directory(d, max_items=500)
    data['unit_dirs'] = unit_dirs
    suspicious = []
    cutoff = datetime.datetime.now() - datetime.timedelta(days=7)
    for d in ('/etc/systemd/system',):
        if not os.path.isdir(d):
            continue
        for pattern in ('*.service', '*.timer', '*.socket', '*.path', '*.mount'):
            for f in glob.glob(os.path.join(d, pattern)):
                try:
                    st = os.stat(f)
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime)
                    if mtime > cutoff:
                        suspicious.append({
                            'path': f,
                            'mtime': mtime.isoformat(),
                            'content': read_file_lines(f, max_lines=100),
                        })
                except Exception:
                    continue
    data['recently_modified_units'] = suspicious
    return data


def collect_kernel_modules():
    data = {}
    data['lsmod'] = run_command('lsmod 2>/dev/null')
    data['modules_raw'] = read_file_lines('/proc/modules', max_lines=500)
    data['tainted'] = read_file_raw('/proc/sys/kernel/tainted')
    data['kptr_restrict'] = read_file_raw('/proc/sys/kernel/kptr_restrict')
    data['dmesg_restrict'] = read_file_raw('/proc/sys/kernel/dmesg_restrict')
    data['perf_event_paranoid'] = read_file_raw('/proc/sys/kernel/perf_event_paranoid')
    data['unprivileged_bpf_disabled'] = read_file_raw('/proc/sys/kernel/unprivileged_bpf_disabled')
    data['modprobe_config'] = {
        'content': read_file_lines('/etc/modprobe.conf'),
        'd': {f: read_file_lines(f) for f in glob.glob('/etc/modprobe.d/*')},
    }
    data['blacklist'] = {f: read_file_lines(f) for f in glob.glob('/etc/modprobe.d/*blacklist*')}

    tainted_modules = []
    mod_dir = '/sys/module'
    if os.path.isdir(mod_dir):
        for mod in os.listdir(mod_dir):
            taint_path = os.path.join(mod_dir, mod, 'taint')
            if os.path.exists(taint_path):
                try:
                    with open(taint_path) as f:
                        taint = f.read().strip()
                    if taint:
                        tainted_modules.append({'module': mod, 'taint': taint})
                except Exception:
                    continue
    data['tainted_modules'] = tainted_modules
    return data


def collect_ld_preload():
    data = {}
    if os.path.exists('/etc/ld.so.preload'):
        data['ld_so_preload'] = {
            'content': read_file_lines('/etc/ld.so.preload'),
            'metadata': get_file_metadata('/etc/ld.so.preload'),
        }
    data['env_LD_PRELOAD'] = os.environ.get('LD_PRELOAD')
    data['env_LD_LIBRARY_PATH'] = os.environ.get('LD_LIBRARY_PATH')
    data['env_LD_AUDIT'] = os.environ.get('LD_AUDIT')
    suspicious = []
    for d in glob.glob('/proc/[0-9]*'):
        try:
            with open(os.path.join(d, 'environ'), 'rb') as f:
                env_data = f.read().decode('utf-8', errors='replace')
            found = {}
            for kv in env_data.split('\0'):
                if kv.startswith('LD_PRELOAD='):
                    found['LD_PRELOAD'] = kv[11:]
                elif kv.startswith('LD_AUDIT='):
                    found['LD_AUDIT'] = kv[9:]
            if found:
                found['pid'] = int(os.path.basename(d))
                suspicious.append(found)
        except Exception:
            continue
    data['processes_with_ld_preload'] = suspicious
    return data


def collect_pam():
    pam = {}
    for f in sorted(glob.glob('/etc/pam.d/*')):
        if os.path.isfile(f):
            pam[f] = {
                'content': read_file_lines(f, max_lines=100),
                'metadata': get_file_metadata(f),
            }
    if os.path.exists('/etc/pam.conf'):
        pam['/etc/pam.conf'] = {
            'content': read_file_lines('/etc/pam.conf'),
            'metadata': get_file_metadata('/etc/pam.conf'),
        }
    return pam


def collect_suid_sgid():
    dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin',
            '/usr/local/sbin', '/opt', '/usr/lib', '/usr/libexec']
    result = []
    seen = set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            for root, subdirs, files in os.walk(d):
                if root.count(os.sep) - d.count(os.sep) > 3:
                    subdirs[:] = []
                    continue
                for f in files:
                    p = os.path.join(root, f)
                    if p in seen:
                        continue
                    seen.add(p)
                    try:
                        st = os.lstat(p)
                        if st.st_mode & (0o4000 | 0o2000):
                            result.append({
                                'path': p,
                                'mode': oct(st.st_mode),
                                'uid': st.st_uid,
                                'gid': st.st_gid,
                                'metadata': get_file_metadata(p),
                            })
                    except Exception:
                        continue
        except Exception:
            continue
    return result


def collect_environment():
    return {
        'current': dict(os.environ),
        'path': os.environ.get('PATH'),
        'shell': os.environ.get('SHELL'),
        'term': os.environ.get('TERM'),
        'ssh_connection': os.environ.get('SSH_CONNECTION'),
        'ssh_client': os.environ.get('SSH_CLIENT'),
        'histfile': os.environ.get('HISTFILE'),
        'histfilesize': os.environ.get('HISTFILESIZE'),
        'histcontrol': os.environ.get('HISTCONTROL'),
        'histtimeformat': os.environ.get('HISTTIMEFORMAT'),
    }


def collect_recent_etc_changes(days=7):
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    recent = []
    dirs = ['/etc', '/var/spool/cron', '/var/spool/cron/crontabs', '/root']
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            for root, subdirs, files in os.walk(d):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        st = os.stat(p)
                        mtime = datetime.datetime.fromtimestamp(st.st_mtime)
                        if mtime > cutoff:
                            recent.append({
                                'path': p,
                                'mtime': mtime.isoformat(),
                                'size': st.st_size,
                                'mode': oct(st.st_mode),
                            })
                    except Exception:
                        continue
        except Exception:
            continue
    recent.sort(key=lambda x: x['mtime'], reverse=True)
    return recent[:300]


def collect_at_jobs():
    data = {}
    data['atq'] = run_command('atq 2>/dev/null')
    data['spool'] = {}
    for d in ('/var/spool/at', '/var/spool/atjobs', '/var/spool/atspool', '/var/spool/cron/atjobs'):
        if os.path.isdir(d):
            data['spool'][d] = list_directory(d, max_items=100)
    data['at_allow'] = read_file_lines('/etc/at.allow')
    data['at_deny'] = read_file_lines('/etc/at.deny')
    return data


def collect_security_modules():
    return {
        'selinux_status': run_command('sestatus 2>/dev/null') or run_command('getenforce 2>/dev/null'),
        'selinux_enforce_file': read_file_raw('/sys/fs/selinux/enforce'),
        'selinux_config': read_file_lines('/etc/selinux/config'),
        'apparmor_status': run_command('aa-status 2>/dev/null') or run_command('apparmor_status 2>/dev/null'),
        'apparmor_profiles': list_directory('/etc/apparmor.d', max_items=200) if os.path.isdir('/etc/apparmor.d') else None,
        'grsec': os.path.exists('/proc/sys/kernel/grsecurity'),
    }


def collect_pkg_history():
    return {
        'apt_history': read_file_lines('/var/log/apt/history.log', max_lines=100),
        'apt_term': read_file_lines('/var/log/apt/term.log', max_lines=100),
        'dpkg_log': read_file_lines('/var/log/dpkg.log', max_lines=100),
        'yum_log': read_file_lines('/var/log/yum.log', max_lines=100),
        'dnf_log': read_file_lines('/var/log/dnf.log', max_lines=100),
        'pacman_log': read_file_lines('/var/log/pacman.log', max_lines=100),
        'rpm_recent': run_command('rpm -qa --last 2>/dev/null | head -100'),
        'installed_apt': run_command('apt list --installed 2>/dev/null | head -500'),
        'installed_rpm': run_command('rpm -qa 2>/dev/null | head -500'),
        'installed_pacman': run_command('pacman -Q 2>/dev/null | head -500'),
        'snap_list': run_command('snap list 2>/dev/null'),
        'flatpak_list': run_command('flatpak list 2>/dev/null'),
    }


def collect_containers():
    data = {'docker': {}, 'podman': {}, 'sockets': {}}
    data['docker']['ps'] = run_command('docker ps -a --no-trunc 2>/dev/null')
    data['docker']['images'] = run_command('docker images 2>/dev/null')
    data['docker']['networks'] = run_command('docker network ls 2>/dev/null')
    data['docker']['volumes'] = run_command('docker volume ls 2>/dev/null')
    data['docker']['info'] = run_command('docker info 2>/dev/null')
    data['docker']['compose_ps'] = run_command('docker-compose ps 2>/dev/null')
    data['podman']['ps'] = run_command('podman ps -a 2>/dev/null')
    data['podman']['images'] = run_command('podman images 2>/dev/null')
    data['sockets'] = {
        '/var/run/docker.sock': os.path.exists('/var/run/docker.sock'),
        '/run/podman/podman.sock': os.path.exists('/run/podman/podman.sock'),
        '/run/containerd/containerd.sock': os.path.exists('/run/containerd/containerd.sock'),
    }
    return data


def collect_dmesg():
    return {
        'dmesg_tail': run_command('dmesg 2>/dev/null | tail -300'),
        'dmesg_warnings': run_command(
            'dmesg 2>/dev/null | grep -iE "(error|warn|oops|panic|BUG|taint|segfault)" | tail -100'
        ),
        'kern_log': read_file_lines('/var/log/kern.log', max_lines=100),
        'journal_recent_errors': run_command('journalctl -p err -b --no-pager 2>/dev/null | tail -100'),
        'journal_boot': run_command('journalctl --list-boots --no-pager 2>/dev/null | tail -20'),
    }


def collect_autostart():
    autostart = {}
    for home in get_user_homes():
        user = os.path.basename(home)
        ads = os.path.join(home, '.config', 'autostart')
        if os.path.isdir(ads):
            user_entries = {'listing': list_directory(ads, max_items=50)}
            files = {}
            for f in glob.glob(os.path.join(ads, '*.desktop')):
                files[f] = {'content': read_file_lines(f), 'metadata': get_file_metadata(f)}
            user_entries['files'] = files
            autostart[user] = user_entries
    if os.path.isdir('/etc/xdg/autostart'):
        global_entries = {'listing': list_directory('/etc/xdg/autostart', max_items=100)}
        files = {}
        for f in glob.glob('/etc/xdg/autostart/*.desktop'):
            files[f] = {'content': read_file_lines(f), 'metadata': get_file_metadata(f)}
        global_entries['files'] = files
        autostart['/etc/xdg/autostart'] = global_entries
    return autostart


def collect_all():
    collectors = {
        'metadata': lambda: {
            'collector_version': '2.0',
            'hostname': os.uname().nodename,
            'kernel': os.uname().release,
            'uid': os.geteuid(),
            'user': pwd.getpwuid(os.geteuid()).pw_name if os.geteuid() >= 0 else None,
            'timestamp': datetime.datetime.now().isoformat(),
        },
        'system': collect_system_info,
        'processes': collect_processes,
        'network': collect_network,
        'ip_route_arp': collect_ip_route_arp,
        'last_logins': collect_last_logins,
        'logged_users': collect_logged_users,
        'logs': collect_logs,
        'command_history': collect_command_history,
        'mounts': collect_mounts,
        'users': collect_user_accounts,
        'user_dotfiles': collect_user_dotfiles,
        'ssh': collect_ssh_artifacts,
        'tool_configs': collect_tool_configs,
        'suspicious_dirs': collect_suspicious_dirs,
        'file_metadata': collect_file_metadata,
        'file_hashes': collect_file_hashes,
        'writable_path_dirs': collect_writable_path_dirs,
        'lsof_version': collect_lsof_version,
        'cron': collect_cron_jobs,
        'persistence': collect_persistence,
        'systemd': collect_systemd,
        'kernel_modules': collect_kernel_modules,
        'ld_preload': collect_ld_preload,
        'pam': collect_pam,
        'suid_sgid': collect_suid_sgid,
        'environment': collect_environment,
        'recent_etc_changes': collect_recent_etc_changes,
        'at_jobs': collect_at_jobs,
        'security_modules': collect_security_modules,
        'pkg_history': collect_pkg_history,
        'containers': collect_containers,
        'dmesg': collect_dmesg,
        'autostart': collect_autostart,
    }
    data = {}
    for name, func in collectors.items():
        try:
            data[name] = func()
        except Exception as e:
            data[name] = {'_error': f'{type(e).__name__}: {e}'}
    return data


def main():
    parser = argparse.ArgumentParser(description='Linux forensics artifact collector')
    parser.add_argument('-o', '--output', default='artifacts.json', help='Output JSON file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress progress output')
    parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    args = parser.parse_args()

    def log(msg):
        if not args.quiet:
            print(msg, file=sys.stderr)

    if os.geteuid() != 0:
        log('Warning: not running as root - some artifacts may be inaccessible')

    log('Collecting artifacts...')
    data = collect_all()

    log(f'Serializing to {args.output}')
    try:
        indent = None if args.compact else 2
        json_str = json.dumps(data, indent=indent, ensure_ascii=False, default=str, skipkeys=True)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_str)
        log(f'Done. Saved to {args.output}')
    except Exception as e:
        print(f'Error writing JSON: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
```

## Возможности

Все сборщики изолированы друг от друга: исключение в одном не прерывает работу остальных. Ошибка сохраняется в соответствующем разделе под ключом `_error`.

### Метаданные запуска
- Версия коллектора, hostname, kernel, `uid`, имя пользователя, ISO-таймстемп запуска.

### Система
- `uname` (sysname, nodename, release, version, machine).
- `/proc/version`, `/etc/os-release` (с fallback на `lsb-release`, `redhat-release`).
- `/etc/localtime`, `/proc/uptime`, вывод `uptime -p`, `timedatectl`, `hostnamectl`.
- Таймстемп `btime` из `/proc/stat`.

### Процессы
- Сырой вывод `ps auxwf`.
- Структурированный список процессов: `pid`, `ppid`, `user`, `cpu`, `mem`, `vsz`, `rss`, `tty`, `stat`, `start`, `time`, `command`.
- `cmdline` всех процессов из `/proc/<pid>/cmdline`.
- **Подозрительные процессы** — бинарь в `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, удалённый исполняемый файл (`exe (deleted)`), признак `exe_in_tmp`.
- Пример kernel-потоков (cmdline в квадратных скобках).

### Сеть
- `ss -tupln`, `netstat -plunto` — сырой и структурированный вывод.
- Установленные соединения (`ss state established`) и слушающие сокеты.
- Конфиги: `/etc/network/interfaces`, DHCP-lease (NetworkManager и dhcp), `ifcfg-*`.
- Firewall: `iptables`, `ip6tables`, `nftables`, `ufw`, `firewalld`.
- `sysctl` (`/etc/sysctl.conf` и `/etc/sysctl.d/*`), `ip_forward`.
- Маршрутизация и ARP: `ip addr`, `ip route`, `ip neigh`, `ip link`, `arp -an`, а также `/proc/net/arp`, `/proc/net/route`, `/proc/net/dev`, `/proc/net/tcp`, `/proc/net/udp`.

### Логины
- `last --time-format iso -Faiwx` — сырой вывод + структурированный парсинг (ISO-таймстемпы и duration вытягиваются регулярками).
- `who`, `w`, `users`, `lastb` (неудачные входы), `faillog -a`.

### Логи
- Системные и прикладные логи (`auth.log`, `secure`, `cron`, `dpkg`, `apt`, `audit`, `syslog`, `messages`, `kern.log`, `daemon.log`, `debug`, `user.log`, `maillog`, `yum`, `dnf`, `pacman`).
- Для бинарных `lastlog`, `btmp`, `wtmp` — только метаданные, без чтения содержимого.
- Флаг наличия systemd-journal и список его директорий.

### История команд
- Для каждого домашнего каталога — `.bash_history`, `.zsh_history`, `.sh_history`, `.ksh_history`, `.csh_history`, `.tcsh_history`, `.ash_history`, а также `.python_history`, `.node_repl_history`, `.irb_history`, `.pry_history`, `.mysql_history`, `.psql_history`, `.sqlite_history`, `.viminfo`, `.lesshst`, `.wget-hsts`, `.perldb`, `.rediscli_history`, `.gdb_history`, `.history`.
- Дополнительно — любой `.*_history` / `.*history` в домашнем каталоге пользователя.
- Для каждой истории — содержимое (последние 50 строк) и метаданные файла.

### Монтирования
- `/proc/mounts` и `/etc/mtab` — сырой и структурированный (device, mountpoint, fstype, options, dump, pass).
- `mount`, `findmnt -A`, `/etc/fstab`, `/etc/fstab.d/*`.

### Пользователи и группы
- `/etc/passwd` — сырой и структурированный (username, password, uid, gid, gecos, home, shell).
- `/etc/shadow`, `/etc/gshadow` с метаданными.
- `/etc/group` — сырой и структурированный (groupname, gid, members).
- `/etc/sudoers`, `/etc/sudoers.d/*`.
- `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/bashrc`, `/etc/environment`.
- `/etc/securetty`, `/etc/login.defs`, `/etc/hosts.allow`, `/etc/hosts.deny`.

### Dot-файлы пользователей
- `.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile`, `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`, `.zlogout`, `.kshrc`, `.cshrc`, `.tcshrc`, `.vimrc`, `.inputrc`, `.selected_editor`, `.xsession`, `.xinitrc`, `.xprofile`, `.tmux.conf`, `.screenrc`.
- Для каждого — содержимое и метаданные.

### SSH
- Для каждого пользователя: `.ssh/authorized_keys`, `known_hosts`, `config`, `environment`, `authorized_keys2`, приватные ключи (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`) — метаданные, `.pub` — содержимое.
- Глобально: `/etc/ssh/sshd_config`, `ssh_config`, `sshd_config.d/*`, `ssh_host_*_key.pub`.

### Конфиги инструментов
Для каждого пользователя — из списка `rel_paths`:
- `.netrc`, `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`;
- `.aws/credentials`, `.aws/config`, `.azure/azureProfile.json`, `.config/gcloud/credentials.db`;
- `.kube/config`, `.docker/config.json`;
- `.wgetrc`, `.curlrc`, `.pgpass`, `.my.cnf`, `.mongorc.js`;
- `.eslintrc`, `.editorconfig`, `.config/gh/hosts.yml`, `.config/git/config`.
- Файлы < 1 МБ читаются, для остальных — только метаданные.

### Подозрительные директории
- `/tmp`, `/var/tmp`, `/dev/shm`, `/var/run`, `/var/spool`, `/run`, `/run/user`.
- Список файлов с размером, mode, uid, gid, mtime, симлинк-флагом; отдельно — скрытые файлы.

### Метаданные и хэши файлов
- Важные файлы (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/environment`, `/etc/ld.so.preload`, `/etc/profile`, `/etc/bash.bashrc`, `/etc/rc.local`, PAM-конфиги, `authorized_keys` root и др.) — size, mode, uid/gid, owner/group, atime, mtime, ctime.
- SHA-256 и базовые метаданные для критичных бинарей (`ls`, `ps`, `ss`, `netstat`, `sshd`, `sudo`, `ssh`, `login`, `passwd`, `bash`, `sh`, `python3`, `curl`, `wget`, `docker`, `systemctl`, `init` и др.).
- Каталоги из `$PATH` с флагом writable.

### Cron
- `/etc/crontab`, `/etc/cron.d/*` — сырой и структурированный (schedule, user, command). Поддерживаются `@reboot`, `@daily` и др.
- `/var/spool/cron/*`, `/var/spool/cron/crontabs/*` — user-crontab'ы (без поля user).

### Персистентность
- `/etc/rc.local`, `/etc/rc.d/rc.local`, `/etc/init.d/rc.local`.
- `/etc/cron.hourly`, `.daily`, `.weekly`, `.monthly`.
- `/etc/init.d`, `/etc/rc*.d`.
- `/etc/motd`, `/etc/issue`, `/etc/issue.net`, `/etc/update-motd.d`.
- `/etc/ld.so.conf`, `/etc/ld.so.conf.d/*`.
- `/etc/skel`.

### systemd
- `systemctl list-units`, `list-unit-files`, `list-timers`.
- Список включённых сервисов.
- Содержимое `/etc/systemd/system`, `/lib/systemd/system`, `/usr/lib/systemd/system`.
- **Недавно изменённые** unit-файлы (`*.service`, `*.timer`, `*.socket`, `*.path`, `*.mount`) в `/etc/systemd/system` за последние 7 дней — с содержимым.

### Kernel-модули и hardening
- `lsmod`, `/proc/modules`.
- `/proc/sys/kernel/tainted`, `kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid`, `unprivileged_bpf_disabled`.
- `/etc/modprobe.conf`, `/etc/modprobe.d/*`, blacklist-файлы.
- Список tainted-модулей (читается `/sys/module/<mod>/taint`).

### LD_PRELOAD / LD_AUDIT
- `/etc/ld.so.preload` с метаданными.
- `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` в окружении коллектора.
- Процессы, у которых в `/proc/<pid>/environ` встречаются `LD_PRELOAD` или `LD_AUDIT`.

### PAM
- `/etc/pam.d/*` и `/etc/pam.conf` — содержимое и метаданные.

### SUID/SGID
- Рекурсивный поиск по `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/usr/lib`, `/usr/libexec` (глубина до 3 уровней).

### Окружение
- Текущие переменные окружения и ключевые: `PATH`, `SHELL`, `TERM`, `SSH_CONNECTION`, `SSH_CLIENT`, `HISTFILE`, `HISTFILESIZE`, `HISTCONTROL`, `HISTTIMEFORMAT`.

### Недавние изменения в `/etc`
- Файлы, изменённые за последние 7 дней, в `/etc`, `/var/spool/cron`, `/var/spool/cron/crontabs`, `/root`.
- Сортировка по mtime, до 300 записей.

### AT-задания
- `atq`, содержимое `/var/spool/at*`, `/etc/at.allow`, `/etc/at.deny`.

### Модули безопасности
- SELinux: `sestatus`/`getenforce`, `/sys/fs/selinux/enforce`, `/etc/selinux/config`.
- AppArmor: `aa-status`/`apparmor_status`, `/etc/apparmor.d`.
- Наличие grsecurity.

### История пакетов
- `apt`, `dpkg`, `yum`, `dnf`, `pacman` — логи.
- Последние установленные RPM, полные списки APT/RPM/pacman (первые 500).
- `snap list`, `flatpak list`.

### Контейнеры
- Docker: `ps -a`, `images`, `network ls`, `volume ls`, `info`, `docker-compose ps`.
- Podman: `ps -a`, `images`.
- Наличие сокетов `docker.sock`, `podman.sock`, `containerd.sock`.

### dmesg и журнал
- `dmesg | tail -300`, отфильтрованные ошибки/предупреждения/taint/panic.
- `/var/log/kern.log` (последние 100 строк).
- `journalctl -p err -b`, список boot'ов.

### Autostart (X11/DE)
- `~/.config/autostart/*.desktop` для каждого пользователя.
- `/etc/xdg/autostart/*.desktop`.

## Требования

- Python 3.8+
- Только стандартная библиотека. Внешних зависимостей нет.
- Опционально `lsof`, `ss`, `netstat`, `iptables`, `nft`, `ufw`, `firewall-cmd`, `systemctl`, `journalctl`, `docker`, `podman`, `rpm`, `dpkg`, `apt`, `pacman`, `snap`, `flatpak`, `atq`, `sestatus`, `aa-status`. При отсутствии утилиты раздел просто останется `None` или с `_error`.

## Использование

```bash
sudo python3 collector.py
sudo python3 collector.py -o /tmp/artifacts.json
sudo python3 collector.py -o artifacts.json --compact
sudo python3 collector.py -q
```
## Опции
```
    -o, --output PATH — файл для сохранения JSON (по умолчанию artifacts.json).

    -q, --quiet — не выводить прогресс в stderr.

    --compact — компактный JSON без отступов.
```
Запуск без root возможен, но многие артефакты (/etc/shadow, /proc/<pid>/environ, /var/log/audit, SUID-поиск) будут недоступны. Скрипт выводит предупреждение, но продолжает работу.
Формат вывода

Один JSON-файл со следующими ключами верхнего уровня:
```text

metadata, system, processes, network, ip_route_arp, last_logins,
logged_users, logs, command_history, mounts, users, user_dotfiles,
ssh, tool_configs, suspicious_dirs, file_metadata, file_hashes,
writable_path_dirs, lsof_version, cron, persistence, systemd,
kernel_modules, ld_preload, pam, suid_sgid, environment,
recent_etc_changes, at_jobs, security_modules, pkg_history,
containers, dmesg, autostart
```

Каждый раздел — либо структурированный объект/список, либо None, либо {"_error": "..."} при исключении внутри сборщика.

## Архитектура

   - Набор функций collect_*, каждая возвращает сериализуемый dict/list/str/None.

   - Единый реестр collectors в collect_all — словарь {name: callable}, что позволяет легко добавлять/отключать разделы.

   - Все вызовы внешних утилит идут через run_command / run_command_full с timeout и errors='replace', поэтому «висящие» утилиты не блокируют сбор.

   - Файлы читаются с errors='replace' и ограничением по числу строк (max_lines), чтобы не раздувать JSON.

   - Для больших бинарных логов (lastlog, btmp, wtmp) сохраняются только метаданные.

   - Структурирование парсеров (parse_ss_tupln, parse_netstat_plunto, parse_last, parse_mounts, parse_passwd, parse_group, parse_crontab) отделено от сборщиков и легко тестируется изолированно.

   - parse_last корректно обрабатывает ISO-таймстемпы (--time-format iso) и duration через регулярки, а также сохраняет сырую строку.

## Ограничения

   - На больших системах (десятки тысяч файлов в /usr/bin, сотни unit-файлов, тысячи процессов) сбор может занимать десятки секунд и давать JSON десятки-сотни МБ. Рекомендуется использовать --compact и не читать полный ps auxwf на системах с большой нагрузкой.

   - Поиск SUID/SGID использует os.walk с ограничением глубины — на кастомных деревьях /opt результат может быть неполным.

   - psutil не используется, поэтому некоторые поля (vsz, rss) зависят от формата вывода ps, который может отличаться между дистрибутивами (BusyBox, BSD-ps).

   - parse_ss_tupln рассчитан на штатный iproute2 ss; парсер netstat -plunto — на Linux net-tools.

   - Содержимое shadow/gshadow/SSH-ключей пишется в JSON как есть. Обращайтесь с файлом как с чувствительным: шифруйте, ограничивайте доступ (chmod 600), передавайте по защищённым каналам.

   - Проверки, зависящие от внешних утилит, зависят от их наличия и прав. В контейнерах без systemd, docker, auditd соответствующие разделы будут пустыми.

   - recent_etc_changes и recently_modified_units смотрят на 7 дней вперёд от момента запуска; для длительных расследований окно нужно расширять параметром.

## Безопасность

   - Скрипт не пишет в систему, не устанавливает и не изменяет файлы (только читает и один раз создаёт выходной JSON).

   - Все команды запускаются через subprocess.run(shell=True, ...) с фиксированными строками — внешнего ввода в команды нет, но при доработках не передавайте в run_command аргументы из ненадёжных источников.

   - Учитывайте, что собранный JSON содержит потенциально чувствительные данные: хэши паролей shadow, приватные SSH-ключи (метаданные), токены в .npmrc/.netrc/.aws/credentials, историю команд и переменные окружения. Обращайтесь с артефактами соответственно.
