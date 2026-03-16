import platform
import getpass
import socket
import ctypes
import os
import subprocess
import re
import json
from datetime import datetime
import time
import urllib.request
import urllib.error
import ssl
import shutil
import base64
from pathlib import Path
import ast
import sys
import signal
CONFIG_DEFAULTS = {
    "AGENT_NAME": "test1",
    "AUTH_TOKEN": "testtoken",
    "SERVER_URL": "https://127.0.0.1:8000/",
    "SERVER_TIMEOUT": 5,
    "SLEEPTIME": 60,
    "DISARM": True,
    "IPTABLES_PATH": "iptables",
    "PORTS": [81],
    "SERVICES": ["AxInstSV"],
    "PACKAGES": [""],
    "SERVICE_BACKUPS": {},
    "PROTECTED_FOLDERS": ["var/www"],
    "DEBUG_PRINT": True,
    "BACKUPDIR": "",
    "LOGFILE": "log.txt",
    "STATUSFILE": "status.txt",
    "MTU_MIN": 1200,
    "MTU_DEFAULT": 1300,
    "MTU_MAX": 1514,
    "LINUX_DEFAULT_TTL": 64,
    "AGENT_TYPE": "magpie"
}
def service_backup(service):
    system = platform.system()
    if system == "Windows":
        return service_backup_windows(service)
    else:
        return {}
def service_backup_windows(service_name):
    ps_query = r"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) { 
        Write-Output 'NotFound'
    }  else { 
        $obj = New-Object PSObject -Property @{ 
            PathName = $svc.PathName
            StartName = $svc.StartName
            Dependencies = $svc.DependsOn
            DisplayName = $svc.DisplayName
            StartType = $svc.StartMode
        } 
        $obj | ConvertTo-Json
    } 
    """.format(service_name=service_name)
    raw = run_powershell(ps_query).strip()
    if not raw or raw == "NotFound":
        print(f"[ERROR] Service '{service_name}' not found or PowerShell error during query.")
        return None
    try:
        data = json.loads(raw)
        data['StartType'] = data['StartType'].lower()
        if data['Dependencies'] is None:
            data['Dependencies'] = []
        return data
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON configuration for '{service_name}': {e}")
        return None
def load_config(path):
    config = CONFIG_DEFAULTS.copy()
    badPath = False
    if os.path.exists(path):
        with open(path, "r") as f:
            config.update(json.load(f))
    else:
        badPath = True
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    for key, value in config.items():
        if isinstance(value, str):
            config[key] = value.format(
                HOST=config.get("HOST"),
                PORT=config.get("PORT"),
                timestamp=timestamp
            )
    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: 
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")
    return config
def get_iptables_save_path():
    if os.path.exists("/etc/alpine-release"):
        return "/etc/iptables/rules-save"
    if os.path.exists("/etc/redhat-release"):
        return "/etc/sysconfig/iptables"
    try:
        dist_info = platform.freedesktop_os_release()
        id_like = dist_info.get("ID_LIKE", "").lower()
        dist_id = dist_info.get("ID", "").lower()
        if "debian" in id_like or "ubuntu" in dist_id:
            return "/etc/iptables/rules.v4"
    except (AttributeError, OSError):
        if os.path.exists("/etc/debian_version"):
            return "/etc/iptables/rules.v4"
    return "/etc/iptables.rules"
def populate_initial_backups(config, path):
    modified = False
    if config.get("SERVICES") and not config.get("SERVICE_BACKUPS"):
        print("[+] SERVICE_BACKUPS is empty. Initializing from current system state...")
        new_backups = {}
        for svc_name in config["SERVICES"]:
            backup_data = service_backup(svc_name)
            if backup_data:
                new_backups[svc_name] = backup_data
                print(f"    - Snapshotted service: {svc_name}")
        if new_backups:
            config["SERVICE_BACKUPS"] = new_backups
            modified = True
    if modified:
        try:
            with open(path, "w") as f:
                json.dump(config, f, indent=4)
            print(f"[+] Initial configuration persisted to {path}")
        except Exception as e:
            print(f"[-] Failed to persist initial config: {e}")
    return config
CONFIG = load_config("config.json") 
CONFIG = populate_initial_backups(CONFIG, "config.json")
DISARM = CONFIG["DISARM"]
IPTABLES_PATH = CONFIG["IPTABLES_PATH"]
DEBUG_PRINT = CONFIG["DEBUG_PRINT"]
BACKUPDIR = CONFIG["BACKUPDIR"]
LOGFILE = CONFIG["LOGFILE"]
STATUSFILE = CONFIG["STATUSFILE"]
MTU_MIN = CONFIG["MTU_MIN"]
MTU_DEFAULT = CONFIG["MTU_DEFAULT"]
MTU_MAX = CONFIG["MTU_MAX"]
LINUX_DEFAULT_TTL = CONFIG["LINUX_DEFAULT_TTL"]
AGENT_NAME = CONFIG["AGENT_NAME"]
DISARM = CONFIG["DISARM"]
AUTH_TOKEN = CONFIG["AUTH_TOKEN"]
AGENT_TYPE = CONFIG["AGENT_TYPE"]
SERVER_URL = CONFIG["SERVER_URL"]
SERVER_TIMEOUT = CONFIG["SERVER_TIMEOUT"]
SLEEPTIME = CONFIG["SLEEPTIME"]
PORTS = CONFIG["PORTS"]
SERVICES = CONFIG["SERVICES"]
PACKAGES = CONFIG["PACKAGES"]
SERVICE_BACKUPS = CONFIG["SERVICE_BACKUPS"]
PROTECTED_FOLDERS = CONFIG["PROTECTED_FOLDERS"]
if isinstance(PROTECTED_FOLDERS, str):
    PROTECTED_FOLDERS = ast.literal_eval(PROTECTED_FOLDERS)
IPTABLES_SAVE_PATH = get_iptables_save_path()
PAUSED = False
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
def print_debug(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if (DEBUG_PRINT):
        print(msg)
    if LOGFILE:
        if len(LOGFILE) > 0:
            with open(LOGFILE, "a") as f:
                f.write(f"{timestamp} {msg}\n")
    return
def get_platform_dist():
    sys_platform = platform.system()
    if sys_platform == "Windows":
        release, version, csd, ptype = platform.win32_ver()
        return ("Windows", release, version)
    if sys_platform == "Linux":
        if hasattr(platform, 'freedesktop_os_release'):
            try:
                info = platform.freedesktop_os_release()
                return (info.get('ID', 'linux'), info.get('VERSION_ID', ''), info.get('NAME', ''))
            except OSError:
                pass
        if os.path.isfile("/etc/os-release"):
            info = {}
            with open("/etc/os-release") as f:
                for line in f:
                    match = re.match(r'^([A-Z_]+)="?([^"\n]+)"?$', line)
                    if match:
                        info[match.group(1)] = match.group(2)
            return (
                info.get('ID', 'linux'), 
                info.get('VERSION_ID', info.get('VERSION', '')), 
                info.get('PRETTY_NAME', '')
            )
    return (sys_platform, platform.release(), platform.version())
def get_os(simple=False):
    system = platform.system()
    if system == "Linux":
        if simple:
            return get_platform_dist()[1] 
        return ' '.join(get_platform_dist()) 
    if simple:
        return platform.system() 
    return f"{platform.system()} {platform.release()}" 
def get_perms():
    system = platform.system()
    if system == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        domain = os.environ.get("USERDOMAIN", None)
        user = getpass.getuser()
        if domain:
            runAsUser = f"{domain}\\{user}"
        else:
            runAsUser = user
        return is_admin, runAsUser
    if system in ("Linux", "FreeBSD"):
        is_root = (os.geteuid() == 0)
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            runAsUser = sudo_user
        else:
            runAsUser = getpass.getuser()
        return is_root, runAsUser
    print_debug("get_perms(): reached unexpected unsupported OS block")
    return False, runAsUser
def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)) 
        ip_address = s.getsockname()[0]
    except Exception as E:
        ip_address = "0.0.0.0"
        print_debug(f"get_primary_ip(): {E}")
    finally:
        s.close()
    return ip_address
def get_system_details():
    sysInfo = {
        "os": get_os(),
        "executionUser": get_perms()[1],
        "executionAdmin": get_perms()[0],
        "hostname": socket.gethostname(), 
        "ipadd": get_primary_ip()
    }
    return sysInfo
def create_backup_primary(path,backupDir=BACKUPDIR):
    return True, ""
def hash_id(*args):
    combined = "|".join(map(str, args))
    encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
    return encoded
def run_powershell(cmd,noisy=True):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        if noisy:
            print_debug(f"PowerShell error: {result.stderr}")
        return "" 
    return result.stdout
def run_bash(cmd, noisy=True):
    executable_path = shutil.which("bash")
    if not executable_path:
        for path in ["/usr/local/bin/bash", "/bin/sh", "/usr/bin/sh"]:
            if os.path.exists(path):
                executable_path = path
                break
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            executable=executable_path, 
            capture_output=True, 
            text=True,
            check=False 
        )
        if result.returncode != 0:
            if noisy:
                print_debug(f"Shell command failed with exit code {result.returncode}")
                if result.stderr:
                    print_debug(f"Shell stderr: {result.stderr.strip()}")
            return ""
        return result.stdout.strip() or "SUCCESS"
    except FileNotFoundError:
        if noisy:
            print_debug(f"Error: The {executable_path} executable was not found.")
        return ""
def run_git(args, cwd):
    cmd = ["git", "-c", "http.sslVerify=false"] + args
    result = subprocess.run(
        cmd, 
        cwd=cwd, 
        capture_output=True, 
        text=True, 
        shell=(platform.system() == "Windows")
    )
    if result.returncode != 0:
        print_debug(f"Shell command failed with exit code {result.returncode}")
        if result.stderr:
            print_debug(f"Shell stderr: {result.stderr.strip()}")
    return result
def setup_git_agent(repo_dir, protected_folders, systemInfo=None):
    if systemInfo is None:
        systemInfo = get_system_details()
    try:
        if not os.path.exists(repo_dir):
            agent_hash = hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])
            repo_url = f"{SERVER_URL}agent/git/{agent_hash}.git"
            run_git(["clone", repo_url, Path(repo_dir).name], os.path.dirname(Path(repo_dir).resolve()))
        run_git(["config", "user.name", "Agent"], repo_dir)
        run_git(["config", "user.email", f"agent@{systemInfo['hostname']}.local"], repo_dir)
        run_git(["checkout", "-b", "good"], cwd=repo_dir)
        for folder in protected_folders:
            sync_protected_to_repo(repo_dir, folder)
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "initialCommitGood"], cwd=repo_dir)
        run_git(["push", "-u", "origin", "good"], cwd=repo_dir)
        run_git(["checkout", "-b", "bad"], cwd=repo_dir)
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "initialCommitBad"], cwd=repo_dir)
        run_git(["push", "-u", "origin", "bad"], cwd=repo_dir)
        run_git(["checkout", "good"], cwd=repo_dir)
        return True
    except Exception as E:
        print_debug(f"Critical error in setup_git_agent: {E}")
        return False
def audit_command(command,package="",packageManager="apt"):
    return True, True
def get_pause_status(file=STATUSFILE):
    try:
        with open(file,"r+") as f:
            firstline = f.readline().strip()
            if len(firstline) < 1:
                return False,False,0
            preferServer = firstline.lower() == "true"
            pausedUntilEpoch = float(f.readline().strip())
            if round(pausedUntilEpoch) != 0:
                if pausedUntilEpoch > time.time():
                    return preferServer, True, pausedUntilEpoch
                else:
                    f.seek(0)
                    f.write(f"{preferServer}\n0\n")
                    f.truncate()
                    return preferServer, False, 0
            else:
                return preferServer, False, 0
    except FileNotFoundError:
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
    except ValueError:
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
    except Exception as E:
        print_debug(f"get_pause_status(): unknown error - {E}")
        with open(file,"w") as f:
            f.write(f"false\n0\n")
        return False, False, 0
def persist_iptables_rules(noisy=True):
    if shutil.which("service"):
        check_svc = run_bash("service iptables status", noisy=False)
        if check_svc:
            print_debug("Detected RHEL-style iptables; persisting via service...")
            return run_bash("service iptables save", noisy=noisy) != ""
    if shutil.which("netfilter-persistent"):
        print_debug("Detected Debian-style iptables; persisting via netfilter-persistent...")
        return run_bash("netfilter-persistent save", noisy=noisy) != ""
    distro = get_platform_dist()[0].lower() 
    path = ""
    if "debian" in distro or "ubuntu" in distro:
        path = "/etc/iptables/rules.v4"
    elif "rhel" in distro or "centos" in distro or "rocky" in distro:
        path = "/etc/sysconfig/iptables"
    if path:
        print_debug(f"No manager found. Falling back to manual save to {path}...")
        return run_bash(f"{IPTABLES_PATH}-save > {path}", noisy=noisy) != ""
    print_debug("Failed to persist: No known persistence method found for this distro.")
    return False
def send_message(endpoint,oldStatus=True,newStatus=True,message="",systemInfo=get_system_details()):
    if not SERVER_URL:
        return True
    url = SERVER_URL + endpoint
    payload = {
        "name": AGENT_NAME,
        "hostname": systemInfo["hostname"],
        "ip": systemInfo["ipadd"],
        "os": systemInfo["os"],
        "executionUser": systemInfo["executionUser"],
        "executionAdmin": systemInfo["executionAdmin"],
        "auth": AUTH_TOKEN,
        "agent_type": AGENT_TYPE,
        "oldStatus": oldStatus,
        "newStatus": newStatus,
        "message": message
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=SERVER_TIMEOUT, context=CTX) as response:
            if response.getcode() == 200:
                print_debug(f"send_message({url}): sent msg to server: [{oldStatus,newStatus,message}]")
                response_text = response.read().decode('utf-8')
                if endpoint == "agent/beacon/owlet":
                    if response_text != AUTH_TOKEN:
                        AUTH_TOKEN = response_text
                        print_debug(f"send_message({url}): updating auth token value to new value from server {AUTH_TOKEN}")
                return response_text
            else:
                print_debug(f"send_message({url}): Server error: {response.getcode()}")
    except urllib.error.HTTPError as e:
        print_debug(f"[send_message({url}): HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"send_message({url}): URL error: {e.reason}")
    except Exception as e:
        print_debug(f"send_message({url}): Beacon error: {e}")
    return False
def interface_get_primary():
    system = platform.system()
    if system == "Windows":
        return interface_get_primary_windows(get_primary_ip())
    else:
        return interface_get_primary_linux(get_primary_ip())
def interface_get_primary_windows(ip):
    query = f"Get-NetIPAddress -IPAddress '{ip}' | Select-Object -ExpandProperty InterfaceAlias"
    output = run_powershell(query).strip()
    return output if output else None
def interface_get_primary_linux(ip):
    system = platform.system()
    if system == "Linux":
        ip_bin = shutil.which("ip")
        if ip_bin:
            try:
                output = subprocess.check_output([ip_bin, "-j", "addr"], text=True)
                addr_data = json.loads(output)
                for iface in addr_data:
                    for addr in iface.get("addr_info", []):
                        if addr.get("local") == ip:
                            return iface.get("ifname")
            except Exception:
                pass
    ifconfig_bin = shutil.which("ifconfig")
    if ifconfig_bin:
        try:
            output = subprocess.check_output([ifconfig_bin], text=True)
            iface = None
            for line in output.splitlines():
                header_match = re.match(r"^([a-zA-Z0-9._-]+)[:\s]", line)
                if header_match:
                    iface = header_match.group(1)
                if "inet " in line and ip in line:
                    return iface
        except Exception:
            pass
    return None
def interface_address(interface,ip_address,subnet,gateway):
    system = platform.system()
    if system == "Windows":
        return interface_address_windows(interface,ip_address,subnet,gateway)
    else:
        return interface_address_linux(interface,ip_address,subnet,gateway)
def interface_address_windows(interface,ip_address,subnet,gateway):
    issues = []
    query_cmd = fr"Get-NetIPConfiguration -InterfaceAlias '{interface}' | Select-Object IPv4Address, IPv4DefaultGateway | ConvertTo-Json"
    output = run_powershell(query_cmd)
    if not output:
        return False, False, [f"Failed to query interface {interface}"]
    try:
        data = json.loads(output)
    except:
        return False, False, [f"JSON parse error for {interface}"]
    has_address = bool(data.get("IPv4Address"))
    has_gateway = bool(data.get("IPv4DefaultGateway"))
    if has_address and has_gateway:
        return True, True, []
    statusFix = True
    if not has_address:
        set_ip_cmd = fr"New-NetIPAddress -InterfaceAlias '{interface}' -IPAddress {ip_address} -PrefixLength {subnet}"
        if DISARM:
            issues.append(f"Missing IPv4 Address for {interface}, DISARMED.")
            statusFix = False
        else:
            if not run_powershell(set_ip_cmd):
                statusFix = False
                issues.append(f"Failed to restore {ip_address}/{subnet} on {interface}.")
            else:
                issues.append(f"Restored {ip_address}/{subnet} on {interface}.")
    if not has_gateway:
        set_gw_cmd = fr"New-NetRoute -InterfaceAlias '{interface}' -DestinationPrefix '0.0.0.0/0' -NextHop {gateway}"
        if DISARM:
            issues.append(f"Missing Gateway for {interface}, DISARMED.")
            statusFix = False
        else:
            if not run_powershell(set_gw_cmd):
                statusFix = False
                issues.append(f"Failed to restore gateway {gateway} on {interface}.")
            else:
                issues.append(f"Restored gateway {gateway} on {interface}.")
    return False, statusFix, issues
def interface_address_linux(interface, ip_address, subnet, gateway):
    issues = []
    ip_addr_cmd = f"ip addr show dev {interface}"
    addr_output = run_bash(ip_addr_cmd, noisy=True)
    ip_route_cmd = "ip route show default"
    route_output = run_bash(ip_route_cmd, noisy=True)
    if not addr_output:
        print_debug(f"interface_address_linux({interface}): Failed to query interface IP (ip addr)")
        return False, False, [f"Failed to query interface {interface} (ip addr error)."]
    cidr = f"{ip_address}/{subnet}"
    has_address = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output))
    has_gateway = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output))
    old_status = has_address and has_gateway
    new_status = old_status
    if old_status:
        return True, True, []
    status_fix = True
    if not has_address:
        set_ip_cmd = f"ip addr add {cidr} dev {interface}"
        if DISARM:
            issues.append(f"Missing IPv4 Address for interface {interface}, DISARMED.")
            status_fix = False
        else:
            print_debug(f"interface_address_linux({interface}): Setting IP address: {cidr}")
            if not run_bash(set_ip_cmd):
                status_fix = False
                issues.append(f"Missing IPv4 Address for interface {interface}, FAILED to restore {cidr}.")
            else:
                issues.append(f"Missing IPv4 Address for interface {interface}, RESTORED {cidr}.")
    if not has_gateway:
        set_gw_cmd = f"ip route add default via {gateway} dev {interface}"
        if DISARM:
            issues.append(f"Missing Gateway Address for interface {interface}, DISARMED.")
            status_fix = False
        else:
            print_debug(f"interface_address_linux({interface}): Setting gateway address: {gateway}")
            if not run_bash(set_gw_cmd):
                status_fix = False
                issues.append(f"Missing Gateway Address for interface {interface}, FAILED to restore {gateway}.")
            else:
                issues.append(f"Missing Gateway Address for interface {interface}, RESTORED {gateway}.")
    if status_fix:
        addr_output_new = run_bash(ip_addr_cmd, noisy=True)
        route_output_new = run_bash(ip_route_cmd, noisy=True)
        has_address_new = bool(re.search(fr"inet\s+{re.escape(cidr)}\s+", addr_output_new))
        has_gateway_new = bool(re.search(fr"default\s+via\s+{re.escape(gateway)}\s+dev\s+{interface}\s+", route_output_new))
        new_status = has_address_new and has_gateway_new
    else:
        new_status = False 
    return old_status, new_status, issues
def interface_mtu(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    system = platform.system()
    if system == "Windows":
        return interface_mtu_windows(interface,mtu_minimum,mtu_maximum,mtu_default)
    else:
        return interface_mtu_linux(interface,mtu_minimum,mtu_maximum,mtu_default)
def interface_mtu_windows(interface=interface_get_primary(),mtu_minimum=MTU_MIN,mtu_maximum=MTU_MAX,mtu_default=MTU_DEFAULT):
    ps_get_mtu = fr"""
    Get-NetIPInterface -InterfaceAlias "{interface}" -AddressFamily IPv4 |
        Select-Object -ExpandProperty NlMtu
    """
    output = run_powershell(ps_get_mtu).strip()
    if not output:
        return False, False, [f"Failed to query MTU for interface '{interface}' due to PowerShell error."]
    if not output.isdigit():
        return False, False, [f"Failed to query MTU for interface '{interface}' due to invalid PowerShell output parsing."]
    old_mtu = int(output)
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default
        ps_set_mtu = fr'''
        Set-NetIPInterface -InterfaceAlias "{interface}" -NlMtu {new_mtu}
        '''
        if DISARM:
            return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, DISARMED."]
        else:
            if run_powershell(ps_set_mtu):
                return False, True, [f"Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}."]
            else:
                return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to restore new mtu {new_mtu}."]
    return True, True, []
def interface_mtu_linux(interface=interface_get_primary(), mtu_minimum=MTU_MIN, mtu_maximum=MTU_MAX, mtu_default=MTU_DEFAULT):
    ip_get_mtu = f"ip link show dev {interface}"
    output = run_bash(ip_get_mtu)
    if not output:
        return False, False, [f"Failed to query MTU for interface '{interface}' due to shell error."]
    match = re.search(r"mtu\s+(\d+)\s+", output)
    if not match:
        return False, False, [f"Failed to parse MTU for interface '{interface}'. Output: {output}"]
    old_mtu = int(match.group(1))
    if old_mtu < mtu_minimum or old_mtu > mtu_maximum:
        new_mtu = mtu_default
        ip_set_mtu = f"ip link set dev {interface} mtu {new_mtu}"
        if DISARM:
            print_debug(f"DISARMED, but told to update MTU for '{interface}' from {old_mtu} to {new_mtu}")
            return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, DISARMED."]
        else:
            print_debug(f"Updated MTU for '{interface}' from {old_mtu} to {new_mtu}")
            if run_bash(ip_set_mtu):
                output_new = run_bash(ip_get_mtu)
                match_new = re.search(r"mtu\s+(\d+)\s+", output_new)
                if match_new and int(match_new.group(1)) == new_mtu:
                    return False, True, [f"Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}."]
                else:
                    return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to verify new mtu {new_mtu}."]
            else:
                return False, False, [f"Interface {interface}'s MTU was set to {old_mtu}, FAILED to restore new mtu {new_mtu}."]
    return True, True, []
def interface_ttl(interface=interface_get_primary()):
    system = platform.system()
    if system == "Windows":
        return interface_ttl_windows(interface)
    else:
        return interface_ttl_linux(interface)
def interface_ttl_windows():
    check_script = r"""
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    if (Test-Path -Path "$path\DefaultTTL" -ErrorAction SilentlyContinue) {
        Write-Output 'True'
    }
    elseif (Test-Path -Path "$path\DefaultCurHopLimit" -ErrorAction SilentlyContinue) {
        Write-Output 'True'
    }
    else {
        Write-Output 'False'
    }
    """
    result = run_powershell(check_script).strip()
    if result:
        delete_script = r"""
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        if (Test-Path "$path\DefaultTTL" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $path -Name "DefaultTTL"
        }
        if (Test-Path "$path\DefaultCurHopLimit" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $path -Name "DefaultCurHopLimit"
        }
        Write-Output 'Deleted'
        """
        if DISARM:
            return False, False, [f"Bad system TTL set, DISARMED."]
        else:
            ps_result = run_powershell(delete_script).strip()
            if ps_result:
                return False, True, [f"Bad system TTL set, RESTORED default TTL."]
            return False, False, [f"Bad system TTL set, FAILED to restore default TTL."]
    return True, True, []
def interface_ttl_linux():
    issues = []
    IPV4_TTL_PARAM = "net.ipv4.ip_default_ttl"
    IPV6_HL_PARAM = "net.ipv6.conf.default.hop_limit" 
    ttl_query_cmd = f"sysctl -n {IPV4_TTL_PARAM}"
    current_ttl_output = run_bash(ttl_query_cmd, noisy=True)
    hl_query_cmd = f"sysctl -n {IPV6_HL_PARAM}"
    current_hl_output = run_bash(hl_query_cmd, noisy=True)
    try:
        current_ttl = int(current_ttl_output)
    except (ValueError, TypeError):
        current_ttl = LINUX_DEFAULT_TTL
    try:
        current_hl = int(current_hl_output)
    except (ValueError, TypeError):
        current_hl = LINUX_DEFAULT_TTL
    ttl_customized = current_ttl != LINUX_DEFAULT_TTL
    hl_customized = current_hl != LINUX_DEFAULT_TTL
    old_status = not (ttl_customized or hl_customized)
    if old_status:
        return True, True, []
    status_fix = True
    if ttl_customized:
        set_ttl_cmd = f"sysctl -w {IPV4_TTL_PARAM}={LINUX_DEFAULT_TTL}"
        if DISARM:
            issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, DISARMED.")
            status_fix = False
        else:
            print_debug(f"Remediating IPv4 TTL from {current_ttl} to {LINUX_DEFAULT_TTL}")
            if run_bash(set_ttl_cmd, noisy=True):
                issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, RESTORED to {LINUX_DEFAULT_TTL}.")
            else:
                issues.append(f"Bad IPv4 TTL ({current_ttl}) detected, FAILED to restore.")
                status_fix = False
    if hl_customized:
        set_hl_cmd = f"sysctl -w {IPV6_HL_PARAM}={LINUX_DEFAULT_TTL}"
        if DISARM:
            issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, DISARMED.")
            status_fix = False
        else:
            print_debug(f"Remediating IPv6 Hop Limit from {current_hl} to {LINUX_DEFAULT_TTL}")
            if run_bash(set_hl_cmd, noisy=True):
                issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, RESTORED to {LINUX_DEFAULT_TTL}.")
            else:
                issues.append(f"Bad IPv6 Hop Limit ({current_hl}) detected, FAILED to restore.")
                status_fix = False
    new_status = False
    if status_fix:
        new_ttl_output = run_bash(ttl_query_cmd, noisy=True)
        new_hl_output = run_bash(hl_query_cmd, noisy=True)
        try:
            new_ttl = int(new_ttl_output)
            new_hl = int(new_hl_output)
        except (ValueError, TypeError):
            return False, False, issues
        new_status = (new_ttl == LINUX_DEFAULT_TTL and new_hl == LINUX_DEFAULT_TTL)
    return old_status, new_status, issues
def interface_down(interface=interface_get_primary()):
    system = platform.system()
    if system == "Windows":
        return interface_down_windows(interface)
    else:
        return interface_down_linux(interface)
def interface_down_windows(interface=interface_get_primary()):
    ps_check = r"""
    $iface = '{interface_name}'
    $int = Get-NetAdapter -Name $iface
    if ($int -eq $null) {
        Write-Output 'NotFound'
    }
    elseif ($int.Status -eq 'Up') {
        Write-Output 'Up'
    }
    else {
        Write-Output 'Down'
    }
    """.format(interface_name=interface)
    status = run_powershell(ps_check).strip()
    if not status:
        return False, False, [f"Interface {interface}'s up/down status cannot be determined due to PowerShell error."]
    if status == "NotFound":
        return False, False, [f"Interface {interface}'s up/down status cannot be determined as it cannot be found."]
    if status == "Down":
        ps_enable = fr"""
        Enable-NetAdapter -Name '{interface}' -Confirm:$false
        """ 
        if DISARM:
            return False, False, [f"Interface {interface} was set to DOWN, DISARMED."]
        else:
            if run_powershell(ps_enable).strip():
                return False, True, [f"Interface {interface} was set to DOWN, RESTORED UP state."]
            return False, False, [f"Interface {interface} was set to DOWN, FAILED to restore UP state."]
    return True, True, []
def interface_down_linux(interface=interface_get_primary()):
    if interface is None:
        interface = interface_get_primary()
    issues = []
    ip_check_cmd = f"ip link show dev {interface}"
    output = run_bash(ip_check_cmd)
    if not output:
        return False, False, [f"Interface {interface} not found."]
    is_up = ",UP" in output or "<UP" in output
    if is_up:
        return True, True, []
    if DISARM:
        return False, False, [f"Interface {interface} is DOWN, DISARMED."]
    if run_bash(f"ip link set dev {interface} up"):
        return False, True, [f"Interface {interface} was DOWN, RESTORED UP state."]
    return False, False, [f"Interface {interface} was DOWN, FAILED to restore."]
def interface_uninstall():
    return False, False, [f"interface_uninstall(): not implemented."]
    system = platform.system()
    if system == "Windows":
        return interface_uninstall_windows()
    else:
        return False, False, [f"interface_uninstall(): not implemented for system {system}."]
def interface_uninstall_windows(interface_name,ipv4_address,prefix_length,gateway,dns_servers):
    issues = []
    ps_detect = fr'''
    $bind = Get-NetAdapterBinding -ComponentID "ms_tcpip" -InterfaceAlias "{interface_name}" -ErrorAction SilentlyContinue
    if ($bind.Enabled -eq $true) {  "Present" }  else {  "Missing" } 
    '''
    ipv4_state = run_powershell(ps_detect).strip()
    old_status = (ipv4_state == "Present")
    if not old_status:
        if DISARM:
            issues.append(f"IPv4 binding missing on {interface_name}, DISARMED.")
            return False, False, issues
        ps_fix = fr'Enable-NetAdapterBinding -ComponentID "ms_tcpip" -InterfaceAlias "{interface_name}"'
        run_powershell(ps_fix)
        issues.append(f"IPv4 binding restored on {interface_name}.")
    ps_restore = r"""
    $params = @{{
        InterfaceAlias = "{interface_name}"
        IPAddress = "{ipv4_address}"
        PrefixLength = {prefix_length}
        DefaultGateway = "{gateway}"
    }}
    New-NetIPAddress @params -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceAlias "{interface_name}" -ServerAddresses ({",".join([f"'{d}'" for d in dns_servers])})
    """.format(interface_name=interface_name, ipv4_address=ipv4_address, prefix_length=prefix_length, gateway=gateway,dns_servers=dns_servers)
    run_powershell(ps_restore)
    issues.append(f"Standard IPv4 configuration applied to {interface_name}.")
    return old_status, True, issues
def interface_main(interface,ip_address,subnet,gateway):
    oldStatus = True
    newStatus = True
    issues = []
    """
    result_oldStatus, result_newStatus, result_issues = interface_uninstall()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    """
    """
    result_oldStatus, result_newStatus, result_issues = interface_address(interface,ip_address,subnet,gateway)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    """
    result_oldStatus, result_newStatus, result_issues = interface_down()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    result_oldStatus, result_newStatus, result_issues = interface_mtu(interface)
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    result_oldStatus, result_newStatus, result_issues = interface_ttl()
    if not result_oldStatus:
        oldStatus = False
    if not result_newStatus:
        newStatus = False
    for issue in result_issues:
        issues.append(issue)
    return oldStatus, newStatus, issues
def firewall_rules_audit(port,direction="in",action="block"):
    system = platform.system()
    if system == "Windows":
        return firewall_rules_audit_windows(port,direction,action)
    else:
        return firewall_rules_audit_linux(port,direction,action)
def firewall_rules_audit_windows(port,direction="in",action="block"):
    ps_query = r"""
    $rules = Get-NetFirewallPortFilter |
        Where-Object {
            $lp = $_.LocalPort
            if ($lp -eq 'Any') { return $true }
            if ($lp -like '*,*') {
                return $lp.Split(',') -contains '{port}'
            }
            if ($lp -like '*-*') {
                $range = $lp.Split('-')
                $a = [int]$range[0].Trim()
                $b = [int]$range[1].Trim()
                return ({port} -ge [int]$a -and {port} -le [int]$b)
            }
            return $lp -eq '{port}'
        } |
        Get-NetFirewallRule |
        Where-Object { $_.Direction -eq '{direction}' -and $_.Action -eq '{action}' } |
        Select-Object Name, DisplayName, Action, Direction, Profile
    if (-not $rules) {
        "none found"
    } else {
        $rules | ConvertTo-Json
    }
    """.format(port=port, direction=direction, action=action)
    output = run_powershell(ps_query).strip()
    if not output:
        return [f"Could not get firewall rule information due to PowerShell error."], dict()
    if output.strip() == "none found":
        return [], dict()
    try:
        rules = json.loads(output)
    except json.JSONDecodeError:
        return [f"Could not get firewall rule information due to PowerShell JSON error."], dict()
    if isinstance(rules, dict):
        rules = [rules]
    return [], rules
def firewall_rules_audit_linux(port, direction="in", action="block"):
    issues = []
    matching_rules = []
    chain = "INPUT" if direction.lower() == "in" else "OUTPUT"
    targets = ["DROP", "REJECT"] if action.lower() == "block" else ["ACCEPT"]
    ip_query_cmd = f"{IPTABLES_PATH} -t filter -S {chain}"
    output = run_bash(ip_query_cmd)
    if not output:
        return [f"Could not run '{ip_query_cmd}' or no rules found."], []
    for index, line in enumerate(output.splitlines(), 1):
        if not line.startswith("-A"):
            continue 
        parts = line.split()
        try:
            target_index = parts.index("-j") + 1
            rule_target = parts[target_index]
        except (ValueError, IndexError):
            continue
        if rule_target in targets:
            port_flag = "--dport" if direction.lower() == "in" else "--sport"
            port_spec = ""
            if port_flag in parts:
                port_spec = parts[parts.index(port_flag) + 1]
            is_port_match = False
            if port_spec:
                if "," in port_spec:
                    if str(port) in port_spec.split(","):
                        is_port_match = True
                elif ":" in port_spec or "-" in port_spec:
                    sep = ":" if ":" in port_spec else "-"
                    try:
                        start, end = map(int, port_spec.split(sep))
                        if start <= int(port) <= end:
                            is_port_match = True
                    except ValueError:
                        issues.append(f"Warning: Could not parse range {port_spec}")
                elif port_spec == str(port):
                    is_port_match = True
            if is_port_match:
                protocol = "all"
                if "-p" in parts:
                    protocol = parts[parts.index("-p") + 1]
                rule_dict = {
                    "Chain": chain,
                    "Index": str(index - 1), 
                    "Protocol": protocol,
                    "Action": rule_target,
                    "Direction": direction.upper(),
                    "DisplayName": line,
                    "Rule_Spec": line
                }
                matching_rules.append(rule_dict)
    return issues, matching_rules
def firewall_rules_delete(rules,port):
    system = platform.system()
    if system == "Windows":
        return firewall_rules_delete_windows(rules,port)
    else:
        return firewall_rules_delete_linux(rules)
def firewall_rules_delete_windows(rules,port):
    issues = []
    status = True
    for rule in rules:
        if (not DISARM):
            delete_cmd = f"Remove-NetFirewallRule -Name '{rule['Name']}'"
            output = run_powershell(delete_cmd)
            if output:
                issues.append(f"SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
            else:
                issues.append(f"FAILED to remove firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
                status = False
        else:
            status = False
            issues.append(f"DISARMED, but told to remove firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.")
    return status, issues
def firewall_rules_delete_linux(rules):
    issues = []
    overall_status = True
    rules.sort(key=lambda r: int(r['Index']), reverse=True)
    for rule in rules:
        chain = rule.get('Chain')
        index = rule.get('Index')
        display_name = rule.get('DisplayName', 'N/A')
        if not (chain and index):
            issues.append(f"FAILED: Rule {display_name} is missing Chain or Index and cannot be deleted.")
            overall_status = False
            continue
        delete_cmd = f"{IPTABLES_PATH} -D {chain} {index}"
        if DISARM:
            issues.append(f"DISARMED, but told to remove firewall rule: {chain} rule #{index}")
            continue
        else:
            print_debug(f"Attempting delete: {delete_cmd} (Rule: {display_name})")
            if run_bash(delete_cmd):
                issues.append(f"SUCCESSFULLY removed firewall rule from {chain} at index #{index}.")
            else:
                issues.append(f"FAILED to remove firewall rule from {chain} at index #{index}. Command failed.")
                overall_status = False
    if not DISARM:
        if overall_status:
            print_debug("Attempting to persist iptables rules...")
            if persist_iptables_rules():
                pass
            else:
                issues.append("WARNING: FAILED to persist iptables changes. Rule deletion is *NOT* permanent.")
                overall_status = False 
    return overall_status, issues
def firewall_rules_create(port,direction,action):
    system = platform.system()
    if system == "Windows":
        return firewall_rules_create_windows(port,direction,action)
    else:
        return firewall_rules_create_linux(port,direction,action)
def firewall_rules_create_windows(port,direction,action):
    rule_name = f"Magpie_Rule_{port}_{direction}_{action}"
    ps_cmd = fr"""
    New-NetFirewallRule -DisplayName "{rule_name}" `
                        -Direction {direction} `
                        -Action {action} `
                        -LocalPort {port} `
                        -Profile Any `
                        -ErrorAction Stop
    """
    if DISARM:
        return False, [f"DISARMED, but told to create firewall rule Magpie_Rule_{port}_{direction}_{action}"] 
    if run_powershell(ps_cmd):
        return True, [f"SUCCESSFULLY created firewall rule Magpie_Rule_{port}_{direction}_{action}"]
    else:
        return False, [f"FAILED to create firewall rule Magpie_Rule_{port}_{direction}_{action}"]
def firewall_rules_create_linux(port, direction, action, protocol="tcp"):
    issues = []
    if direction.lower() == "inbound":
        chain = "INPUT"
        port_flag = "--dport" 
    elif direction.lower() == "outbound":
        chain = "OUTPUT"
        port_flag = "--sport" 
    else:
        return False, [f"FAILED: Invalid direction '{direction}'. Must be 'inbound' or 'outbound'."]
    if action.lower() == "allow":
        target = "ACCEPT"
    elif action.lower() == "block":
        target = "DROP"
    else:
        return False, [f"FAILED: Invalid action '{action}'. Must be 'allow' or 'block'."]
    if protocol.lower() == "tcp" or protocol.lower() == "udp":
        module_spec = f"-m {protocol.lower()}"
    else:
        module_spec = ""
        port_flag = "" 
    rule_spec = f"-p {protocol.lower()} {module_spec} {port_flag} {port} -j {target}"
    iptables_cmd = f"{IPTABLES_PATH} -A {chain} {rule_spec}"
    rule_description = f"{target} on port {port} ({protocol.upper()}) {direction.upper()}"
    if DISARM:
        print_debug(f"firewall_rules_create_linux(): DISARMED, but told to create rule: {iptables_cmd}")
        return False, [f"DISARMED, but told to create firewall rule: {rule_description}"]
    else:
        print_debug(f"Creating iptables rule: {iptables_cmd}")
        if run_bash(iptables_cmd):
            issues.append(f"SUCCESSFULLY created firewall rule: {rule_description} (running kernel).")
            print_debug("Attempting to persist iptables rules...")
            if persist_iptables_rules():
                return False, issues
            else:
                issues.append("FAILED to persist iptables changes. Rule is *NOT* permanent across reboots.")
                return False, issues
        else:
            return False, [f"FAILED to create firewall rule: {rule_description}. Check permissions/syntax."]
def firewall_policy_audit(direction):
    system = platform.system()
    if system == "Windows":
        return firewall_policy_audit_windows(direction)
    else:
        return firewall_policy_audit_linux(direction)
def firewall_policy_audit_windows(direction):
    ps_cmd = f"""
    Get-NetFirewallProfile |
        Select-Object Name, Default{direction}Action |
        ConvertTo-Json
    """
    output = run_powershell(ps_cmd)
    issues = []
    if not output:
        return False, False, [f"Failed to load firewall policy information due to PowerShell error."]
    try:
        profiles = json.loads(output)
    except json.JSONDecodeError:
        return False, False, [f"Failed to load firewall policy information due to could not decode PowerShell JSON output."]
    if isinstance(profiles, dict):
        profiles = [profiles]
    for p in profiles:
        if (p[f"Default{direction}Action"] == "Block"):
            issues.append([f"Default firewall policy on profile {p['Name']} for direction {direction} is set to BLOCK."])
    if issues:
        return True, False, issues
    return True, True, []
def firewall_policy_audit_linux(direction):
    issues = []
    if direction.lower() == "inbound":
        chain = "INPUT"
    elif direction.lower() == "outbound":
        chain = "OUTPUT"
    else:
        return False, False, [f"Failed: Invalid direction '{direction}'. Must be 'Inbound' or 'Outbound'."]
    ip_query_cmd = f"{IPTABLES_PATH} -t filter -S {chain}"
    output = run_bash(ip_query_cmd)
    if not output:
        return False, False, [f"Failed to load iptables policy for {chain} due to shell error."]
    policy_regex = re.compile(fr"^-P\s+{chain}\s+(?P<action>ACCEPT|DROP|REJECT)(?:\s+\[\d+:\d+\])?")
    match = policy_regex.search(output)
    if not match:
        return False, False, [f"Failed to parse iptables policy for {chain}. Unexpected output."]
    default_action = match.group('action')
    if default_action in ["DROP", "REJECT"]:
        issues.append(f"Default firewall policy for {chain} ({direction}) is set to BLOCK ({default_action}).")
        policy_status = False
    else:
        policy_status = True 
    return True, policy_status, issues
def firewall_main(protectedPorts):
    oldStatus = True
    newStatus = True
    issues = []
    for port in protectedPorts:
        result_issues, matched_rules = firewall_rules_audit(port,"in","block")
        if matched_rules:
            oldStatus = False
            remediateStatus, result_issues = firewall_rules_delete(matched_rules,port)
            if not remediateStatus:
                newStatus = False
            for issue in result_issues:
                issues.append(issue)
        else:
            for issue in result_issues:
                issues.append(issue)
        result_issues, matched_rules = firewall_rules_audit(port,"out","block")
        if matched_rules:
            oldStatus = False
            remediateStatus, result_issues = firewall_rules_delete(matched_rules,port)
            if not remediateStatus:
                newStatus = False
            for issue in result_issues:
                issues.append(issue)
        else:
            for issue in result_issues:
                issues.append(issue)
    for direction in ["Inbound","Outbound"]:
        funcStatus, policyStatus, result_issues = firewall_policy_audit(direction)
        if funcStatus:
            if not policyStatus:
                for port in protectedPorts:
                    dirShort = ""
                    if direction == "Inbound":
                        dirShort = "in"
                    else:
                        dirShort = "out"
                    if not firewall_rules_audit(port,dirShort,"allow"):
                        result_status, result_issues = firewall_rules_create(port,direction.lower(),"allow")
                        if not result_status:
                            newStatus = False
                        oldStatus = False
                        msgMain = [f"Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists."]
                        for issue in result_issues:
                            msgMain.append(issue)
                        issues.append(" ".join(msgMain))
        else:
            for issue in result_issues:
                issues.append(issue)
    return oldStatus, newStatus, issues
def apply_security_policy(target_path):
    is_windows = platform.system() == "Windows"
    try:
        if is_windows:
            subprocess.run(["attrib", "-R", "-S", "-H", target_path, "/S", "/D"], capture_output=True)
        else:
            if platform.system() in ["FreeBSD", "Darwin"]:
                subprocess.run(["chflags", "-R", "noschg", target_path], capture_output=True)
            else:
                subprocess.run(["chattr", "-R", "-i", target_path], capture_output=True)
    except Exception:
        pass
    if is_windows:
        cmds = [
            ["icacls", target_path, "/reset", "/T", "/C"],
            ["icacls", target_path, "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C"], 
            ["icacls", target_path, "/grant:r", "*S-1-5-32-545:(OI)(CI)R", "/T", "/C"]  
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)
    else:
        if os.path.isdir(target_path):
            os.chmod(target_path, 0o755) 
        else:
            os.chmod(target_path, 0o744) 
        for root, dirs, files in os.walk(target_path):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o755)
            for f in files:
                os.chmod(os.path.join(root, f), 0o744)
def get_path_slug(path):
    normalized = path.replace('\\', '/')
    clean_path = re.sub(r'^[a-zA-Z]:', '', normalized).lstrip('/')
    slug = re.sub(r'[^a-zA-Z0-9]', '_', clean_path).strip('_')
    return slug if slug else "root_dir"
def sync_protected_to_repo(repo_dir, protected_folder):
    slug = get_path_slug(protected_folder)
    dest_in_repo = os.path.join(repo_dir, slug)
    apply_security_policy(protected_folder)
    if os.path.isfile(protected_folder):
        os.makedirs(dest_in_repo, exist_ok=True)
        shutil.copy2(protected_folder, os.path.join(dest_in_repo, os.path.basename(protected_folder)))
    else:
        shutil.copytree(protected_folder, dest_in_repo, dirs_exist_ok=True, copy_function=shutil.copy2)
    apply_security_policy(dest_in_repo)
def restore_protected_from_repo(repo_dir, protected_folder):
    slug = get_path_slug(protected_folder)
    source_in_repo = os.path.join(repo_dir, slug)
    status = True
    if not os.path.exists(source_in_repo):
        return status
    try:
        if os.path.isfile(protected_folder):
            file_name = os.path.basename(protected_folder)
            shutil.copy2(os.path.join(source_in_repo, file_name), protected_folder)
        else:
            shutil.copytree(source_in_repo, protected_folder, dirs_exist_ok=True, copy_function=shutil.copy2)
        apply_security_policy(protected_folder)
        if platform.system() != "Windows":
            path_str = str(protected_folder).lower()
            if any(x in path_str for x in ['systemd/system', 'init.d', 'rc.d']):
                if shutil.which("systemctl"):
                    if not run_bash("systemctl daemon-reload"):
                        status = False
                elif shutil.which("rc-update"): 
                    if not run_bash("rc-update -u"):
                        status = False
    except Exception as E:
        print_debug(f"restore_protected_from_repo failed on {protected_folder}: {E}")
        status = False
    return status
def get_latest_commit_stats(branch_name, repo_dir):
    result = run_git(["show", "--format=", "--name-status", branch_name], repo_dir)
    if not result or result.returncode != 0:
        return {"count": 0, "files": []}
    lines = result.stdout.strip().split('\n')
    files_info = []
    status_map = {'M': 'Modified', 'A': 'Created', 'D': 'Deleted', 'R': 'Renamed'}
    for line in lines:
        if not line.strip(): continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            status, file_path = parts
            friendly_status = status_map.get(status[0], status) 
            files_info.append(f"{friendly_status}: {file_path}")
    return {"count": len(files_info), "files": files_info}
def file_protect_main(repo_dir, protected_folders):
    try:
        run_git(["checkout", "good"], repo_dir)
        run_git(["pull", "origin", "good"], repo_dir)
        for item in os.listdir(repo_dir):
            if item == ".git": continue
            path = os.path.join(repo_dir, item)
            if os.path.isdir(path): shutil.rmtree(path)
            else: os.remove(path)
        for folder in protected_folders:
            if os.path.exists(folder):
                sync_protected_to_repo(repo_dir, folder)
        run_git(["add", "."], repo_dir)
        diff_check = run_git(["diff", "--cached", "--quiet"], repo_dir)
        if diff_check.returncode != 0:
            try:
                hash_result = run_git(["rev-parse", "--short", "HEAD"], repo_dir)
                good_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else "unknown"
                run_git(["stash"], repo_dir)
                run_git(["checkout", "bad"], repo_dir)
                run_git(["pull", "origin", "bad"], repo_dir)
                run_git(["checkout", "good", "."], repo_dir) 
                run_git(["add", "."], repo_dir)
                run_git(["commit", "--allow-empty", "-m", f"baseline-{good_hash}"], repo_dir)
                if run_git(["stash", "pop"], repo_dir).returncode != 0:
                    run_git(["checkout", "--theirs", "."], repo_dir)
                    run_git(["add", "."], repo_dir)
                    run_git(["commit", "-m", "auto-resolveconflict"], repo_dir)
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                run_git(["add", "."], repo_dir)
                run_git(["commit", "-m", f"auto-malicious-{timestamp}"], repo_dir)
                run_git(["push", "-u", "origin", "bad"], repo_dir)
                changes = get_latest_commit_stats("bad", repo_dir)
                run_git(["checkout", "good"], repo_dir)
                if not DISARM:
                    status = True
                    issues = [f"{changes['count']} unauthorized changes found: {changes['files']}"]
                    is_win = platform.system() == "Windows"
                    for s in SERVICES:
                        cmd = ["net", "stop", s] if is_win else ["systemctl", "stop", s]
                        run_bash(cmd)
                    for folder in protected_folders:
                        if not restore_protected_from_repo(repo_dir, folder):
                            status = False
                            issues.append(f"Failed to restore {folder}")
                    for s in SERVICES:
                        cmd = ["net", "start", s] if is_win else ["systemctl", "start", s]
                        run_bash(cmd)
                    return False, status, issues
                else:
                    return False, False, [f"Changes detected (DISARMED): {changes['files']}"]
            except Exception as E:
                return False, False, [f"Restoration logic failed: {E}"]
        return True, True, []
    except Exception as E:
        return False, False, [f"Integrity check fatal error: {E}"] 
def service_audit(service):
    system = platform.system()
    if system == "Windows":
        return service_audit_windows(service)
    else:
        return service_audit_linux(service)
def service_audit_windows(service_name):
    ps_check = r"""
    $svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    if ($svc -eq $null) {
        Write-Output 'NotFound'
    } else {
        $obj = [PSCustomObject]@{
            Status = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        }
        $obj | ConvertTo-Json
    }
    """.format(service_name=service_name)
    raw = run_powershell(ps_check).strip()
    if not raw or raw == "NotFound":
        return False, False, [f"ServiceNotFound for service {service_name}."]
    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to parse service JSON for {service_name}."]
    current_status = data.get("Status", "")
    current_start = data.get("StartType", "")
    is_running = current_status == "Running"
    is_auto = current_start in ("Automatic", "Auto")
    oldStatus = is_running and is_auto
    newStatus = oldStatus
    issues = []
    if not is_running:
        if DISARM:
            issues.append(f"Service {service_name} not running, DISARMED.")
        else:
            run_powershell(f"Start-Service -Name '{service_name}'")
            verify = run_powershell(f"(Get-Service '{service_name}').Status").strip()
            if verify == "Running":
                issues.append(f"Service {service_name} was stopped, RESTORED to START state.")
                is_running = True
            else:
                issues.append(f"Service {service_name} was stopped, FAILED to start.")
    if not is_auto:
        if DISARM:
            issues.append(f"Service {service_name} not set to automatic, DISARMED.")
        else:
            if run_powershell(f"Set-Service -Name '{service_name}' -StartupType Automatic"):
                issues.append(f"Service {service_name} set to Automatic.")
                is_auto = True
    newStatus = is_running and is_auto
    return oldStatus, newStatus, issues
def service_audit_linux(service_name):
    issues = []
    systemctl_show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(systemctl_show_cmd).strip()
    if not raw or "LoadState=not-found" in raw:
        return False, False, [f"ServiceNotFound: {service_name} is not loaded on this system."]
    data = {}
    for line in raw.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            data[key] = value
    active_state = data.get("ActiveState", "").lower()    
    unit_state = data.get("UnitFileState", "").lower()     
    load_state = data.get("LoadState", "").lower()
    is_running = (active_state == "active")
    is_enabled = unit_state in ["enabled", "enabled-runtime", "static", "indirect"]
    old_status = is_running and is_enabled
    current_running = is_running
    current_enabled = is_enabled
    if not is_running:
        if DISARM:
            issues.append(f"Service {service_name} is {active_state}, DISARMED.")
        else:
            run_bash(f"systemctl start {service_name}")
            if run_bash(f"systemctl is-active {service_name}").strip() == "active":
                issues.append(f"Service {service_name} was {active_state}, RESTORED to active.")
                current_running = True
            else:
                issues.append(f"Service {service_name} FAILED to start.")
    if unit_state == "disabled":
        if DISARM:
            issues.append(f"Service {service_name} is disabled, DISARMED.")
        else:
            if run_bash(f"systemctl enable {service_name}"):
                issues.append(f"Service {service_name} was disabled, RESTORED to enabled.")
                current_enabled = True
            else:
                issues.append(f"Service {service_name} FAILED to enable.")
    elif unit_state == "masked":
        issues.append(f"Service {service_name} is MASKED. Manual intervention required.")
    new_status = current_running and current_enabled
    return old_status, new_status, issues
def service_uninstall(service,package):
    if (not service) and (not package):
        print_debug(f"service_uninstall({service},{package}): provided with empty args despite failsafes elsewhere?")
        return True, True, [] 
    system = platform.system()
    if system == "Windows":
        return service_uninstall_windows(service,package)
    else:
        return service_uninstall_linux(service,package)
def service_uninstall_windows(service, package):
    issues = []
    old_status = False
    pkg_found = False
    if package:
        feat_check = run_powershell(f"Get-WindowsOptionalFeature -Online -FeatureName {package} -ErrorAction SilentlyContinue | ConvertTo-Json")
        if feat_check:
            data = json.loads(feat_check)
            if data.get("State") == "Enabled":
                pkg_found = True
        if not pkg_found:
            if DISARM:
                issues.append(f"Package {package} missing, DISARMED.")
            else:
                run_powershell(f"Enable-WindowsOptionalFeature -Online -FeatureName {package} -All -NoRestart")
                pkg_found = True 
    svc_found = False
    if service:
        svc_check = run_powershell(f"Get-Service -Name {service} -ErrorAction SilentlyContinue")
        svc_found = bool(svc_check)
        if not svc_found:
            issues.append(f"Service {service} missing. Manual reinstallation required.")
    old_status = (pkg_found if package else True) and (svc_found if service else True)
    return old_status, (pkg_found and svc_found), issues
def service_uninstall_linux(service, package):
    issues = []
    is_debian = os.path.exists("/usr/bin/apt-get")
    package_present_initial = False
    if package:
        check_cmd = f"dpkg -l {package}" if is_debian else f"rpm -q {package}"
        res = run_bash(check_cmd, noisy=False)
        package_present_initial = (res != "" and "not installed" not in res.lower())
        if not package_present_initial:
            if DISARM:
                issues.append(f"Missing package {package}, DISARMED.")
            else:
                install_cmd = f"apt-get install -y {package}" if is_debian else f"dnf install -y {package}"
                if run_bash(install_cmd):
                    issues.append(f"Restored package {package} via {'apt' if is_debian else 'dnf'}.")
                else:
                    issues.append(f"FAILED to install package {package}.")
    service_present_initial = False
    if service:
        svc_check = run_bash(f"systemctl show --no-pager {service}")
        service_present_initial = (svc_check != "" and "LoadState=loaded" in svc_check)
        if not service_present_initial and not DISARM:
            svc_check = run_bash(f"systemctl show --no-pager {service}")
            if "LoadState=loaded" in svc_check:
                issues.append(f"Service {service} restored by package installation.")
                service_present_after = True
            else:
                service_present_after = False
        else:
            service_present_after = service_present_initial
    package_present_after = package_present_initial or (not DISARM) 
    oldStatus = (package_present_initial if package else True) and (service_present_initial if service else True)
    newStatus = (package_present_after) and (service_present_after if service else True)
    return oldStatus, newStatus, issues
def service_integrity(service,backupDict):
    system = platform.system()
    if system == "Windows":
        return service_integrity_windows(service,backupDict)
    else:
        return True, True, []
def service_integrity_windows(service_name, backupDict):
    ps_check = r"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) { 
        Write-Output 'NotFound'
    }  else { 
        $obj = New-Object PSObject -Property @{ 
            StartName = $svc.StartName
            PathName = $svc.PathName
            Dependencies = $svc.DependsOn
        } 
        $obj | ConvertTo-Json
    } 
    """.format(service_name=service_name)
    raw = run_powershell(ps_check).strip()
    if not raw:
        return False, False, [f"FAILED to get integrity information for service {service_name}, PowerShell error."]
    oldStatus = True
    newStatus = oldStatus
    issues = []
    if raw == "NotFound" or raw == "":
        oldStatus = False 
        expected_path_name = backupDict.get("PathName", "")
        expected_display_name = backupDict.get("DisplayName", service_name)
        expected_start_type = backupDict.get("StartType", "auto").lower()
        expected_start_name = backupDict.get("StartName", "LocalSystem")
        dependencies_str = "/".join(backupDict.get("Dependencies", []))
        if not expected_path_name:
            issues.append(f"Service {service_name} was MISSING, FAILED to create (PathName not in backupDict).")
            return oldStatus, False, issues
        ps_create = fr"""
        sc.exe create "{service_name}" ^
            binpath= "{expected_path_name}" ^
            displayname= "{expected_display_name}" ^
            start= {expected_start_type} ^
            obj= "{expected_start_name}" ^
            depend= "{dependencies_str}"
        """
        if DISARM:
            issues.append(f"Service {service_name} was MISSING, DISARMED. (Would attempt to create it.)")
            return oldStatus, False, issues 
        else:
            if run_powershell(ps_create):
                issues.append(f"Service {service_name} was MISSING, RESTORED by creating the service.")
                return oldStatus, True, issues 
            else:
                issues.append(f"Service {service_name} was MISSING, FAILED to create service.")
                return oldStatus, False, issues 
    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to get integrity information for service {service_name}, PowerShell JSON parse error. Raw: {raw[:50]}..."]
    current_start_name = data.get("StartName", "")
    current_path_name  = data.get("PathName", "")
    current_dependencies = data.get("Dependencies", [])
    expected_start_name = backupDict.get("StartName", "").strip()
    expected_path_name  = backupDict.get("PathName", "").strip()
    expected_dependencies = backupDict.get("Dependencies", [])
    current_dependencies_sorted = sorted([d.lower() for d in current_dependencies])
    expected_dependencies_sorted = sorted([d.lower() for d in expected_dependencies])
    if (current_start_name != expected_start_name) or (current_path_name.lower().strip() != expected_path_name.lower().strip()) or (current_dependencies_sorted != expected_dependencies_sorted):
        oldStatus = False
    if current_path_name.lower().strip() != expected_path_name.lower().strip():
        ps_path_fix = fr"""
        Stop-Service -Name '{service_name}' -Force -ErrorAction SilentlyContinue | Out-Null
        sc.exe config "{service_name}" binPath= "{expected_path_name}"
        Start-Service -Name '{service_name}' -ErrorAction SilentlyContinue | Out-Null
        """
        if DISARM:
            issues.append(f"Service {service_name} PathName ('{current_path_name}') is incorrect, DISARMED. (Expected: {expected_path_name})")
        else:
            if run_powershell(ps_path_fix):
                issues.append(f"Service {service_name} PathName from ('{current_path_name}') to {expected_path_name} restored. Service stopped/restarted.")
                newStatus = True
            else:
                issues.append(f"Service {service_name} PathName from ('{current_path_name}') to {expected_path_name} restoration FAILED.")
    if current_start_name != expected_start_name:
        ps_start_name_fix = None
        if expected_start_name in ("LocalSystem", "NT AUTHORITY\\LocalSystem"):
             ps_start_name_fix = fr"""sc.exe config "{service_name}" obj= "LocalSystem" password= "" """
        elif expected_start_name in ("LocalService", "NT AUTHORITY\\LocalService"):
             ps_start_name_fix = fr"""sc.exe config "{service_name}" obj= "NT AUTHORITY\LocalService" password= "" """
        if ps_start_name_fix is None:
            issues.append(f"Service {service_name} StartName ('{current_start_name}') is incorrect, expected '{expected_start_name}'. RESTORE IMPOSSIBLE (user account password needed).")
        else:
            if DISARM:
                issues.append(f"Service {service_name} StartName ('{current_start_name}') is incorrect, DISARMED. (Expected: {expected_start_name})")
            else:
                if run_powershell(ps_start_name_fix):
                    issues.append(f"Service {service_name} StartName ('{current_start_name}') restored to '{expected_start_name}'.")
                    newStatus = True
                else:
                    issues.append(f"Service {service_name} StartName ('{current_start_name}') restoration FAILED. (Expected: {expected_start_name})")
    if current_dependencies_sorted != expected_dependencies_sorted:
        dependency_list_str = "/".join(expected_dependencies)
        ps_dep_fix = fr"""
        Stop-Service -Name '{service_name}' -Force -ErrorAction SilentlyContinue | Out-Null
        sc.exe config "{service_name}" depend= "{dependency_list_str}"
        Start-Service -Name '{service_name}' -ErrorAction SilentlyContinue | Out-Null
        """
        if DISARM:
            issues.append(f"Service {service_name} Dependencies are incorrect, DISARMED. (Expected: {expected_dependencies}) (Actual: {current_dependencies_sorted})")
        else:
            if run_powershell(ps_dep_fix):
                issues.append(f"Service {service_name} Dependencies restored to '{expected_dependencies}'. Service stopped/restarted. Old bad dependencies: {current_dependencies_sorted}")
                newStatus = True
            else:
                issues.append(f"Service {service_name} Dependencies restoration FAILED. Old bad dependencies: {current_dependencies_sorted}. Current dependencies: {expected_dependencies}")
    return oldStatus, newStatus, issues
def service_lastrun(service):
    system = platform.system()
    if system == "Windows":
        return service_lastrun_windows(service)
    else:
        return service_lastrun_linux(service)
def service_lastrun_windows(service_name):
    oldStatus = True
    newStatus = True
    issues = []
    ps_check = r"""
    $svc = Get-CimInstance Win32_Service -Filter "Name='{service_name}'"
    if ($null -eq $svc) {{ 
        Write-Output 'NotFound'
    }} else {{ 
        $obj = [PSCustomObject]@{ 
            Status = $svc.State
            ExitCode = $svc.ExitCode
        } 
        $obj | ConvertTo-Json
    }} 
    """.format(service_name=service_name)
    raw = run_powershell(ps_check).strip()
    if not raw or raw == "NotFound":
        return False, False, [f"Status Check: ServiceNotFound {service_name}."]
    try:
        data = json.loads(raw)
    except:
        return False, False, [f"FAILED to parse status for {service_name}."]
    current_status = data.get("Status", "Unknown")
    exit_code = data.get("ExitCode", 0)
    if current_status == "Running":
        return True, True, []
    oldStatus = False
    newStatus = False 
    if exit_code == 0:
        msg = f"Service {service_name} is {current_status}. Last stop was clean (0)."
    elif exit_code == 1066:
        msg = f"Service {service_name} is {current_status}. Stopped with a Service-Specific error (1066)."
    else:
        msg = f"Service {service_name} is {current_status}. Last exit code: {exit_code}."
    issues.append(msg)
    return oldStatus, newStatus, issues
def service_lastrun_linux(service_name):
    oldStatus = True
    newStatus = True
    issues = []
    active_check = run_bash(f"systemctl is-active {service_name}").strip()
    if active_check == "active":
        return True, True, []
    show_cmd = f"systemctl show --no-pager {service_name}"
    raw = run_bash(show_cmd)
    if "LoadState=not-found" in raw:
        return False, False, [f"Status Check: ServiceNotFound {service_name}."]
    data = {}
    for line in raw.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            data[k] = v
    oldStatus = False
    newStatus = False
    exit_status = data.get("ExecMainStatus", "0")
    result = data.get("Result", "unknown")
    analysis_msg = f"Service {service_name} is {active_check}."
    if result != "success":
        analysis_msg += f" Termination reason: {result} (Code: {exit_status})."
    else:
        analysis_msg += " Last exit was successful (0)."
    issues.append(analysis_msg)
    return oldStatus, newStatus, issues
def service_main(services,packages,service_backups):
    if len(services) != len(packages):
        return False, False, [f"service_main({services},{packages}): services and packages lists are not the same size."]
    oldStatus = True
    newStatus = True
    issues = []
    for service,package in zip(services,packages):
        if (not service) and (not package):
            continue
        """
        result_oldStatus, result_newStatus, result_issues = service_uninstall(service,package)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
        """
        try:
            result_oldStatus, result_newStatus, result_issues = service_integrity(service,SERVICE_BACKUPS[service])
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                issues.append(issue)
        except KeyError:
            print_debug(f"service_main(): no backup data available for {service}")
        result_oldStatus, result_newStatus, result_issues = service_audit(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
        result_oldStatus, result_newStatus, result_issues = service_lastrun(service)
        if not result_oldStatus:
            oldStatus = False
        if not result_newStatus:
            newStatus = False
        for issue in result_issues:
            issues.append(issue)
    return oldStatus, newStatus, issues
def pause_countdown(seconds=60):
    return resume(True)
def pause(seconds=60):
    send_message("agent/beacon/magpie",True,True,f"pausing for seconds {seconds}")
    return True
def resume(scheduled=False):
    send_message("agent/beacon/magpie",True,True,f"resuming - scheduled: {scheduled}")
    return True
def reregister():
    send_message("agent/beacon/magpie",True,True,"reregister")
    return True
def init_int_vars(interface=interface_get_primary()):
    system = platform.system()
    if system == "Windows":
        return init_int_vars_windows(interface)
    else:
        return init_int_vars_linux(interface)
def init_int_vars_windows(interface=interface_get_primary()):
    query_cmd = fr"""
        Get-NetIPAddress -InterfaceAlias '{interface}' -AddressFamily IPv4 | 
        Select-Object IPAddress, PrefixLength | ConvertTo-Json
    """
    output = run_powershell(query_cmd).strip()
    ip_address = None
    prefix = None
    gateway = None
    if output:
        try:
            data = json.loads(output)
            if isinstance(data, list):
                data = data[0]
            ip_address = data.get("IPAddress")
            prefix = data.get("PrefixLength")
        except json.JSONDecodeError:
            print_debug(f"init_int_vars_windows({interface}): JSON parse error.")
    query_gw = fr"""
        Get-NetIPConfiguration -InterfaceAlias '{interface}' | 
        Select-Object -ExpandProperty IPv4DefaultGateway | Select-Object NextHop | ConvertTo-Json
    """
    gw_output = run_powershell(query_gw).strip()
    if gw_output:
        try:
            gw_data = json.loads(gw_output)
            if isinstance(gw_data, list):
                gateway = gw_data[0].get("NextHop")
            else:
                gateway = gw_data.get("NextHop")
        except json.JSONDecodeError:
             print_debug(f"init_int_vars_windows({interface}): Gateway JSON parse error.")
    print_debug(f"init_int_vars_windows({interface}): {ip_address} {prefix} {gateway}")
    return ip_address, prefix, gateway
def init_int_vars_linux(interface):
    ip_address = None
    prefix = None
    gateway = None
    try:
        cmd = ["ip", "-j", "addr", "show", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        addr_data = json.loads(result.stdout)
        if addr_data and "addr_info" in addr_data[0]:
            for addr in addr_data[0]["addr_info"]:
                if addr.get("family") == "inet":
                    ip_address = addr.get("local")
                    prefix = addr.get("prefixlen")
                    break 
    except Exception as e:
        print_debug(f"init_int_vars_linux({interface}): IP query failed: {e}")
    try:
        cmd = ["ip", "-j", "route", "show", "default", "dev", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        route_data = json.loads(result.stdout)
        if route_data:
            gateway = route_data[0].get("gateway") or route_data[0].get("via")
    except Exception as e:
        print_debug(f"init_int_vars_linux({interface}): Gateway query failed: {e}")
    print_debug(f"init_int_vars_linux({interface}): {ip_address} {prefix} {gateway}")
    return ip_address, prefix, gateway
def test_network():
    interface = interface_get_primary() 
    ip_address,prefix,gateway = init_int_vars()
    print_debug(f"interface_get_primary(): {interface}")
    print_debug(f"interface_main({interface,ip_address,prefix,gateway}): {interface_main(interface,ip_address,prefix,gateway)}")
    print_debug(f"firewall_main(['81','82']): {firewall_main(['81','82'])}")
def test_service():
    service = "AxInstSV"
    print_debug(f"service_audit({service}): {service_audit(service)}")
def test_main():
    print_debug(f"get_system_details(): {get_system_details()}")
    test_service()
def signal_handler(sig, frame):
    print_debug("Service stopping due to receiving signal handler")
    sys.exit(0)
def main(stop_event=None):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    global PAUSED
    ip_address,prefix,gateway = init_int_vars()
    systemInfo = get_system_details()
    agent_id = hash_id(AGENT_NAME, systemInfo["hostname"], systemInfo["ipadd"], systemInfo["os"])
    repo_url = os.path.join(f"{SERVER_URL}agent/git",f"{agent_id}.git")
    repo_dir = f"{os.path.join(os.path.dirname(os.path(__file__).resolve()),f'{agent_id}.git')}"
    send_message("agent/beacon/magpie",True,True,f"Register")
    setup_git_agent(repo_dir,PROTECTED_FOLDERS)
    oldStatus = True
    newStatus = True
    oldIssues = []
    newIssues = []
    for service in SERVICES:
        try:
            if not SERVICE_BACKUPS[service]:
                SERVICE_BACKUPS[service] = service_backup(service)
        except KeyError:
                SERVICE_BACKUPS[service] = service_backup(service)
    print_debug(f"main(): System details - {get_system_details()}")
    while True:
        oldStatus = True
        newStatus = True
        pausedEpochServer = send_message("agent/get_pause")
        if pausedEpochServer:
            pausedEpochServer = float(pausedEpochServer)
        else:
            pausedEpochServer = -1
        pausePreferServer, pausedStatus, pausedEpochLocal = get_pause_status()
        if pausedEpochServer != -1:
            if pausedEpochServer == 0:
                if pausePreferServer:
                    with open(STATUSFILE,"w") as f:
                        f.write(f"true\n0\n")
                    pausedStatus = False
                    pausedEpochLocal = 0
            else:
                if pausedEpochServer == 1:
                    with open(STATUSFILE,"w") as f:
                        f.write(f"{pausePreferServer}\n0\n")
                    pausedStatus = False
                    pausedEpochLocal = 0
                else:
                    with open(STATUSFILE,"w") as f:
                        f.write(f"{pausePreferServer}\n{pausedEpochServer}\n")
                    pausedStatus = True
                    pausedEpochLocal = pausedEpochServer
        sent_msg = False
        suppressed_send = False
        if PAUSED != pausedStatus:
            PAUSED = pausedStatus
            if PAUSED:
                suppressed_send = True
                send_message("agent/beacon/magpie",False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message("agent/beacon/magpie",True,True,f"Agent moved into ACTIVE status (from PAUSE)")
        if not PAUSED:
            print_debug(f"main(): running firewall checks")
            result_oldStatus, result_newStatus, result_issues = firewall_main(PORTS)
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                newIssues.append(f"Firewall - {issue}")
                print_debug(newIssues[-1])
                if newIssues[-1] not in oldIssues:
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
                    sent_msg = True
                else:
                    suppressed_send = True
            print_debug(f"main(): running interface checks")
            result_oldStatus, result_newStatus, result_issues = interface_main(interface_get_primary(),ip_address,prefix,gateway)
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                newIssues.append(f"Interface - {issue}")
                print_debug(newIssues[-1])
                if newIssues[-1] not in oldIssues:
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
                    sent_msg = True
                else:
                    suppressed_send = True
            print_debug(f"main(): running service checks")
            result_oldStatus, result_newStatus, result_issues = service_main(SERVICES,PACKAGES,SERVICE_BACKUPS)
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                newIssues.append(f"Service - {issue}")
                print_debug(newIssues[-1])
                if newIssues[-1] not in oldIssues:
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
                    sent_msg = True
                else:
                    suppressed_send = True
            print_debug(f"main(): running file checks")
            result_issues_main = []
            result_oldStatus, result_newStatus, result_issues = file_protect_main(repo_dir,PROTECTED_FOLDERS)
            if not result_oldStatus:
                oldStatus = False
            if not result_newStatus:
                newStatus = False
            for issue in result_issues:
                result_issues_main.append(f"{issue}")
            for issue in result_issues_main:
                newIssues.append(f"File - {issue}")
                print_debug(newIssues[-1])
                if newIssues[-1] not in oldIssues:
                    send_message("agent/beacon/magpie",result_oldStatus,result_newStatus,newIssues[-1])
                    sent_msg = True
                else:
                    suppressed_send = True
            if not sent_msg:
                if suppressed_send:
                    send_message("agent/beacon/magpie",True,True,"no new issues; at least one prior issue still exists but suppressing redundant alert")
                else:
                    send_message("agent/beacon/magpie",True,True,"all good")
            print_debug(f"main(): oldStatus - {oldStatus}")
            print_debug(f"main(): newStatus - {newStatus}")
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")
            oldIssues = newIssues
            newIssues = []
        else:
            if not suppressed_send:
                send_message("agent/beacon/magpie",True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        """
        system = platform.system()
        if system == "Windows":
            if len(sys.argv) > 1:
                for _ in range(sleeptime):
                    if stop_event is not None:
                        if win32event.WaitForSingleObject(stop_event, 0) == win32event.WAIT_OBJECT_0:
                            print_debug("Service stop requested during sleep.")
                            return
                    time.sleep(1)
            else:
                time.sleep(sleeptime)
        else:
            time.sleep(sleeptime)
        """
        time.sleep(SLEEPTIME)
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()