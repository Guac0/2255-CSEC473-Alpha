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
import signal
import sys
from datetime import timedelta
from abc import ABC, abstractmethod
import struct
import sqlite3
import grp
import pwd
import shlex
try:
    import win32evtlog
    import win32net
    import win32netcon
    import win32security
    import pywintypes
    import win32evtlogutil
    import winreg
    import win32serviceutil
    import win32service
    import win32event
    WINDOWS_LIBS_LOADED = True
except ImportError:
    WINDOWS_LIBS_LOADED = False
CONFIG_DEFAULTS = {
    "AGENT_NAME": "kingfisher",
    "AUTH_TOKEN": "testtoken",
    "SLEEPTIME": 60,
    "SERVER_URL": "https://127.0.0.1:8000/",
    "SERVER_TIMEOUT": 5,
    "DEBUG_PRINT": True,
    "LOGFILE": "log.txt",
    "STATUSFILE": "status.txt",
    "STATE_FILE": "state.json",
    "AGENT_TYPE": "kingfisher",
    "DISARM": True
}
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
                HOST=config.get("SERVER_URL").split(":")[-1],
                PORT=":".join(config.get("SERVER_URL").split(":")[:-1]),  
                timestamp=timestamp
            )
    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: 
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")
    return config
CONFIG = load_config("config.json") 
DEBUG_PRINT = CONFIG["DEBUG_PRINT"]
LOGFILE = CONFIG["LOGFILE"]
STATUSFILE = CONFIG["STATUSFILE"]
AGENT_NAME = CONFIG["AGENT_NAME"]
AUTH_TOKEN = CONFIG["AUTH_TOKEN"]
AGENT_TYPE = CONFIG["AGENT_TYPE"]
SERVER_URL = CONFIG["SERVER_URL"]
SERVER_TIMEOUT = CONFIG["SERVER_TIMEOUT"]
SLEEPTIME = CONFIG["SLEEPTIME"]
STATE_FILE = CONFIG["STATE_FILE"]
DISARM = CONFIG["DISARM"]
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
    return False, ""
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
            res = run_bash(f"{ip_bin} -j addr", noisy=False)
            if res.returncode == 0 and res.stdout.strip():
                try:
                    addr_data = json.loads(res.stdout)
                    for iface in addr_data:
                        for addr in iface.get("addr_info", []):
                            if addr.get("local") == ip:
                                return iface.get("ifname")
                except (json.JSONDecodeError, KeyError) as e:
                    print_debug(f"interface_get_primary_linux(): Failed to parse 'ip -j' output: {e}")
            else:
                print_debug(f"interface_get_primary_linux(): falling back to ifconfig mode as ip binary not found")
    ifconfig_bin = shutil.which("ifconfig")
    if ifconfig_bin:
        res = run_bash(ifconfig_bin, noisy=False)
        if res.returncode == 0 and res.stdout.strip():
            iface = None
            for line in res.stdout.splitlines():
                header_match = re.match(r"^([a-zA-Z0-9._-]+)[:\s]", line)
                if header_match:
                    iface = header_match.group(1)
                if "inet " in line and ip in line:
                    return iface
        elif res.returncode != 0:
            print_debug(f"interface_get_primary_linux(): ifconfig failed with code {res.returncode} and error {res.stderr.strip()}")
    return None
def get_system_details():
    sysInfo = {
        "os": get_os(),
        "executionUser": get_perms()[1],
        "executionAdmin": get_perms()[0],
        "hostname": socket.gethostname(), 
        "ipadd": get_primary_ip()
    }
    return sysInfo
def run_powershell(cmd,noisy=True):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        if noisy:
            print_debug(f"PowerShell error: {result.stderr.strip()}")
        return "" 
    return result.stdout
def run_bash(cmd, shellStatus=True, noisy=True):
    executable_path = shutil.which("bash")
    if not executable_path:
        for path in ["/usr/local/bin/bash", "/bin/sh", "/usr/bin/sh"]:
            if os.path.exists(path):
                executable_path = path
                break
    try:
        result = subprocess.run(
            cmd,
            shell=shellStatus,
            executable=executable_path,
            capture_output=True, 
            text=True,
            check=False 
        )
        if result.returncode != 0 and noisy:
            print_debug(f"run_bash(): Command failed [{result.returncode}]: {cmd}")
            if result.stderr:
                print_debug(f"    Stderr: {result.stderr.strip()}")
        return result
    except Exception as e:
        if noisy:
            print_debug(f"run_bash(): System error executing command: {e}")
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(e))
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
def get_admin_group_name():
    try:
        sid = win32security.StringToSid("S-1-5-32-544")
        name, domain, type = win32security.LookupAccountSid(None, sid)
        print_debug(f"get_admin_group_name - selected {name} as Administrators group name")
        return name 
    except Exception as E:
        print_debug(f"ERROR: get_admin_group_name - unexpected error, defaulting to Administrators: {E}")
        return "Administrators"
def get_user_provider():
    os_type = platform.system().lower()
    if os_type == "windows":
        print_debug("System detected: Windows. Loading WindowsProvider.")
        return WindowsProvider()
    elif os_type == "linux":
        try:
            os_info = platform.freedesktop_os_release()
            distro_id = os_info.get("ID", "").lower()
            distro_like = os_info.get("ID_LIKE", "").lower()
        except AttributeError:
            distro_id = "unknown"
            distro_like = ""
        if distro_id in ["debian", "ubuntu", "kali"]:
            print_debug(f"System detected: {distro_id.capitalize()}. Loading DebianProvider.")
            return DebianProvider()
        elif distro_id in ["rhel", "fedora", "rocky", "almalinux"] or "rhel" in distro_like:
            print_debug(f"System detected: {distro_id.upper()}. Loading RHELProvider.")
            return RHELProvider()
        if distro_id == "alpine":
            print_debug("System detected: Alpine. Loading AlpineProvider.")
            return AlpineProvider()
        else:
            print_debug(f"Unknown Linux distro ({distro_id}). Defaulting to DebianProvider logic.")
            return DebianProvider()
    elif os_type == "freebsd":
        print_debug("System detected: FreeBSD. Loading FreeBSDProvider.")
        return FreeBSDProvider()
    else:
        raise OSError(f"{AGENT_TYPE} does not currently support the operating system: {os_type}")
def send_message(endpoint,oldStatus=True,newStatus=True,message="",authInfo=None,systemInfo=get_system_details()):
    global AUTH_TOKEN
    if not SERVER_URL:
        return True
    url = SERVER_URL + endpoint
    if authInfo != None:
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
            "message": message,
            "timestamp": authInfo["timestamp"],
            "user": authInfo["user"],
            "srcip": authInfo["srcip"],
            "login_type": authInfo["login_type"],
            "successful": authInfo["successful"]
        }
    else:
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
                if endpoint == f"agent/beacon/{AGENT_TYPE}":
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
    return ""
class UserProvider(ABC):
    @abstractmethod
    def get_all_users(self):
        pass
    @abstractmethod
    def change_password(self, username, new_password):
        pass
    @abstractmethod
    def lock_account(self, username, should_be_locked):
        pass
    @abstractmethod
    def set_admin_status(self, username, should_be_admin):
        pass
    @abstractmethod
    def delete_user(self, username):
        pass
    @abstractmethod
    def create_user(self, username, password, should_be_admin): 
        pass
if WINDOWS_LIBS_LOADED:
    class WindowsProvider(UserProvider):
        def __init__(self):
            self.server = None
            self.admingrpname = get_admin_group_name()
        def get_all_users(self):
            try:
                users = []
                resume = 0
                while True:
                    try:
                        data, total, resume = win32net.NetUserEnum(
                            self.server, 
                            3, 
                            win32netcon.FILTER_NORMAL_ACCOUNT, 
                            resume
                        )
                        for user in data:
                            groups = win32net.NetUserGetLocalGroups(self.server, user['name'])
                            is_admin = self.admingrpname in groups 
                            is_locked = bool(user['flags'] & win32netcon.UF_ACCOUNTDISABLE)
                            last_login_ts = int(user['last_logon'])
                            account_type = "local"
                            if user['flags'] & win32netcon.UF_WORKSTATION_TRUST_ACCOUNT:
                                account_type = "domain"
                            elif user['auth_flags'] & win32netcon.AF_OP_PRINT: 
                                account_type = "domain"
                            users.append({
                                'username': user['name'],
                                'admin': is_admin,
                                'locked': is_locked,
                                'last_login': last_login_ts,
                                'account_type': account_type
                            })
                    except Exception as E:
                        print_debug(f"WARNING: get_all_users - unexpected error: {E}")
                    if not resume:
                        break
                print_debug(f"OK: Read {len(users)} users from system")
                return users
            except Exception as E:
                print_debug(f"ERROR: get_all_users - {E}")
                return {}
        def change_password(self, username, new_password):
            if DISARM:
                print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
                return False
            try:
                user_info = {'password': new_password}
                win32net.NetUserSetInfo(self.server, username, 1003, user_info)
                print_debug(f"OK: Changed password for user {username} to 'REDACTED'")
                return True
            except Exception as E:
                print_debug(f"ERROR: change_password({username}, 'REDACTED') - {E}")
                return False
        def lock_account(self, username, should_be_locked):
            if DISARM:
                print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
                return False
            try:
                user_info = win32net.NetUserGetInfo(self.server, username, 1008)
                if should_be_locked:
                    user_info['flags'] |= win32netcon.UF_ACCOUNTDISABLE
                else:
                    user_info['flags'] &= ~win32netcon.UF_ACCOUNTDISABLE
                win32net.NetUserSetInfo(self.server, username, 1008, user_info)
                if should_be_locked:
                    print_debug(f"OK: Locked/disabled account for user {username}")
                else:
                    print_debug(f"OK: Unlocked/enabled account for user {username}")
                return True
            except Exception as E:
                print_debug(f"ERROR: lock_account({username}) - {E}")
                return False
        def set_admin_status(self, username, should_be_admin):
            if DISARM:
                print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
                return False
            try:
                if should_be_admin:
                    win32net.NetLocalGroupAddMembers(self.server, self.admingrpname, 3, [username])
                    print_debug(f"OK: Added Admin access to user {username}")
                else:
                    win32net.NetLocalGroupDelMembers(self.server, self.admingrpname, [username])
                    print_debug(f"OK: Removed Admin access to user {username}")
                return True
            except Exception as E:
                print_debug(f"ERROR: set_admin_status({username}, {should_be_admin}) - {E}")
                return False
        def delete_user(self, username):
            if DISARM:
                print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
                return False
            try:
                win32net.NetUserDel(self.server, username)
                print_debug(f"OK: Deleted user {username}")
                return True
            except Exception as E:
                print_debug(f"ERROR: delete_user({username}) - {E}")
                return False
        def create_user(self, username, password, should_be_admin):
            if DISARM:
                print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
                return False
            try:
                user_data = {
                    'name': username,
                    'password': password,
                    'priv': win32netcon.USER_PRIV_USER,
                    'comment': f"Created by {AGENT_TYPE}",
                    'flags': win32netcon.UF_SCRIPT | win32netcon.UF_NORMAL_ACCOUNT
                }
                win32net.NetUserAdd(self.server, 1, user_data)
                print_debug(f"OK: Created regular user {username} with password 'REDACTED'")
                if should_be_admin:
                    if not self.set_admin_status(username, True):
                        raise Exception("set_admin_status returned False")
                return True
            except Exception as E:
                print_debug(f"ERROR: create_user({username},'redacted',{should_be_admin}) - {E}")
                return False
else:
    class WindowsProvider(UserProvider):
        def __init__(self, *args, **kwargs):
            print_debug(f"CRITICAL: WindowsProvided inited but WINDOWS_LIBS_LOADED is false!")
            pass
        def get_all_users(self): return False
        def change_password(self, username, new_password): return False
        def lock_account(self, username): return False
        def set_admin_status(self, username, should_be_admin): return False
        def delete_user(self, username): return False
        def create_user(self, username, password, should_be_admin): return False
class DebianProvider(UserProvider):
    def __init__(self):
        self.admingrpname = "sudo"
    def _get_last_login(self, username, uid):
        binary_path = '/var/log/lastlog'
        if os.path.exists(binary_path):
            fmt = 'I32s256s' 
            size = struct.calcsize(fmt)
            try:
                with open(binary_path, 'rb') as f:
                    f.seek(uid * size)
                    data = f.read(size)
                    if data:
                        return int(struct.unpack(fmt, data)[0])
            except: pass
        db_path = '/var/lib/lastlog/lastlog2.db'
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT time FROM lastlog2 WHERE user=?", (username,))
                row = cursor.fetchone()
                conn.close()
                if row: return int(row[0])
            except: pass
        print_debug("_get_last_login - falling back to CLI method")
        res = run_bash(f"lastlog -u {shlex.quote(username)}")
        if "**Never logged in**" not in res.stdout.strip():
            return 1 
        return 0
    def get_all_users(self):
        try:
            users = []
            try:
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []
            for p in pwd.getpwall():
                try:
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue
                    is_locked = False
                    result = run_bash(f"passwd -S {shlex.quote(p.pw_name)}", noisy=False)
                    try:
                        if result.stdout.split()[1] == 'L':
                            is_locked = True
                    except Exception as E:
                        print_debug(f"get_all_users(): Error when running passwd -S {shlex.quote(p.pw_name)}, defaulting user state to unlocked")
                        pass
                    account_type = "local"
                    with open('/etc/passwd', 'r') as f:
                        if p.pw_name not in f.read():
                            account_type = "domain"
                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': account_type
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")
            print_debug(f"OK: Read {len(users)} users from system")
            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []
    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            cmd = f"echo '{username}:{new_password}' | chpasswd"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"chpasswd command failed - {result.stdout.strip()}")
            print_debug(f"OK: Changed password for user {username} to 'REDACTED'")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}, 'REDACTED') - {E}")
            return False
    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            action = "--lock" if should_be_locked else "--unlock"
            result = run_bash(f"usermod {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"usermod {action} failed - {result.stderr.strip()}")
            status = "Locked/disabled" if should_be_locked else "Unlocked/enabled"
            print_debug(f"OK: {status} account for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False
    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                res = run_bash(f"usermod -aG {self.admingrpname} {shlex.quote(username)}")
            else:
                res = run_bash(f"gpasswd -d {shlex.quote(username)} {self.admingrpname}")
            if (res.returncode != 0) and should_be_admin: 
                raise Exception(f"Admin status update failed - {res.stderr.strip()}")
            status = "Added Admin access to" if should_be_admin else "Removed Admin access from"
            print_debug(f"OK: {status} user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}, {should_be_admin}) - {E}")
            return False
    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            result = run_bash(f"userdel {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"userdel command failed - {result.stderr.strip()}")
            print_debug(f"OK: Deleted user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False
    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            create_cmd = f"useradd -m -s /bin/bash {shlex.quote(username)}"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"useradd command failed - {result.stderr.strip()}")
            print_debug(f"OK: Created regular user {username} with password 'REDACTED'")
            if not self.change_password(username, password):
                raise Exception("Initial password set failed")
            if should_be_admin:
                if not self.set_admin_status(username, True):
                    raise Exception("Initial admin promotion failed")
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}, 'REDACTED', {should_be_admin}) - {E}")
            return False
class RHELProvider(UserProvider):
    def __init__(self):
        self.admingrpname = "wheel"
    def _get_last_login(self, username, uid):
        binary_path = '/var/log/lastlog'
        if os.path.exists(binary_path):
            fmt = 'I32s256s' 
            size = struct.calcsize(fmt)
            try:
                with open(binary_path, 'rb') as f:
                    f.seek(uid * size)
                    data = f.read(size)
                    if data:
                        return int(struct.unpack(fmt, data)[0])
            except: pass
        db_path = '/var/lib/lastlog/lastlog2.db'
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT time FROM lastlog2 WHERE user=?", (username,))
                row = cursor.fetchone()
                conn.close()
                if row: return int(row[0])
            except: pass
        print_debug("_get_last_login - falling back to CLI method")
        res = run_bash(f"lastlog -u {shlex.quote(username)}", noisy=False)
        if "**Never logged in**" not in res.stdout.strip():
            return 1 
        return 0
    def get_all_users(self):
        try:
            users = []
            try:
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []
            for p in pwd.getpwall():
                try:
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue
                    is_locked = True
                    result = run_bash(f"passwd -S {shlex.quote(p.pw_name)}", noisy=False)
                    if result.stdout.strip():
                        status_char = result.stdout.strip().split()[1]
                        if status_char in ['P', 'PS']:
                            is_locked = False
                    account_type = "local"
                    with open('/etc/passwd', 'r') as f:
                        if p.pw_name not in f.read():
                            account_type = "domain"
                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': account_type
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")
            print_debug(f"OK: Read {len(users)} users from RHEL system")
            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []
    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            cmd = f"echo '{username}:{new_password}' | chpasswd"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"chpasswd command failed - {result.stderr.strip()}")
            print_debug(f"OK: Changed password for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}) - {E}")
            return False
    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            action = "--lock" if should_be_locked else "--unlock"
            result = run_bash(f"usermod {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"usermod {action} failed - {result.stdout.strip()}")
            status = "Locked/disabled" if should_be_locked else "Unlocked/enabled"
            print_debug(f"OK: {status} account for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False
    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                res = run_bash(f"usermod -aG {self.admingrpname} {shlex.quote(username)}")
            else:
                res = run_bash(f"gpasswd -d {shlex.quote(username)} {self.admingrpname}")
            if (res.returncode != 0) and should_be_admin:
                raise Exception(f"Admin status update failed - {res.stderr}")
            status = "Added Admin access to" if should_be_admin else "Removed Admin access from"
            print_debug(f"OK: {status} user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}) - {E}")
            return False
    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            result = run_bash(f"userdel {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"userdel command failed - {result.stderr.strip()}")
            print_debug(f"OK: Deleted user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False
    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            create_cmd = f"useradd -m {shlex.quote(username)}"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"useradd command failed - {result.stderr.split()}")
            if not self.change_password(username, password):
                raise Exception("Initial password set failed")
            if should_be_admin:
                if not self.set_admin_status(username, True):
                    raise Exception("Initial admin promotion failed")
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}) - {E}")
            return False
class AlpineProvider(UserProvider):
    def __init__(self):
        self.admingrpname = "wheel"
    def _get_last_login(self, username, uid):
        binary_path = '/var/log/lastlog'
        if os.path.exists(binary_path):
            pass
        res = run_bash(f"last | grep {shlex.quote(username)}", noisy=False)
        if res.stdout.strip():
            return 1
        return 0
    def get_all_users(self):
        try:
            users = []
            try:
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []
            for p in pwd.getpwall():
                try:
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue
                    is_locked = False
                    result = run_bash(f"passwd -S {shlex.quote(p.pw_name)}")
                    if result.returncode == 0:
                        parts = result.stdout.strip().split()
                        if len(parts) >= 2:
                            if parts[1] == 'L':
                                is_locked = True
                    else:
                        print_debug(f"get_all_users() - failed to execute passwd -S - {result.stderr.stdout()}")
                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': "local"
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")
            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []
    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            cmd = f"echo '{username}:{new_password}' | chpasswd"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"chpasswd failed - {result.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}) - {E}")
            return False
    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            action = "-L" if should_be_locked else "-U"
            result = run_bash(f"usermod {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"usermod {action} failed - {result.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False
    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                res = run_bash(f"addgroup {shlex.quote(username)} {self.admingrpname}")
            else:
                res = run_bash(f"delgroup {shlex.quote(username)} {self.admingrpname}")
            if (res.returncode != 0) and should_be_admin:
                raise Exception(f"Admin status update failed - {res.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}) - {E}")
            return False
    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            result = run_bash(f"deluser {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"deluser command failed - {result.stderr.strip()}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False
    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            create_cmd = f"adduser -D -s /bin/sh {shlex.quote(username)}"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"adduser command failed - {result.stderr.strip()}")
            self.change_password(username, password)
            if should_be_admin:
                self.set_admin_status(username, True)
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}) - {E}")
            return False
class FreeBSDProvider(UserProvider):
    def __init__(self):
        self.admingrpname = "wheel"
    def _get_last_login(self, username, uid):
        res = run_bash(f"last -n 1 {shlex.quote(username)}", noisy=False)
        if "never logged in" not in res.stdout.strip().lower():
            return 1 
        return 0
    def get_all_users(self):
        try:
            users = []
            try:
                admins = grp.getgrnam(self.admingrpname).gr_mem
            except KeyError as E:
                print_debug(f"ERROR: get_all_users - failed to get admin list: {E}")
                admins = []
            for p in pwd.getpwall():
                try:
                    if p.pw_uid < 1000 and p.pw_name != "root":
                        continue
                    is_locked = False
                    user_info = run_bash(f"pw user show {shlex.quote(p.pw_name)}", noisy=False)
                    if "*LOCKED*" in user_info.stdout.strip():
                        is_locked = True
                    users.append({
                        'username': p.pw_name,
                        'admin': p.pw_name in admins or p.pw_name == "root",
                        'locked': is_locked,
                        'last_login': self._get_last_login(p.pw_name, p.pw_uid),
                        'account_type': "local"
                    })
                except Exception as E:
                    print_debug(f"WARNING: get_all_users iteration for {p.pw_name} failed: {E}")
            print_debug(f"OK: Read {len(users)} users from system")
            return users
        except Exception as E:
            print_debug(f"ERROR: get_all_users - {E}")
            return []
    def change_password(self, username, new_password):
        if DISARM:
            print_debug(f"OK: Attempted to change password for user {username} to 'REDACTED', but DISARMED")
            return False
        try:
            cmd = f"echo {shlex.quote(new_password)} | pw usermod {shlex.quote(username)} -h 0"
            result = run_bash(cmd)
            if result.returncode != 0:
                raise Exception(f"pw usermod password update failed - {result.stderr.split()}")
            print_debug(f"OK: Changed password for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: change_password({username}) - {E}")
            return False
    def lock_account(self, username, should_be_locked):
        if DISARM:
            print_debug(f"OK: Attempted to change lock state for user {username} to {should_be_locked}', but DISARMED")
            return False
        try:
            action = "Locked/disabled" if should_be_locked else "Unlocked/enabled"
            result = run_bash(f"pw {action} {shlex.quote(username)}")
            if result.returncode != 0:
                raise Exception(f"pw {action} failed - {result.stderr.strip()}")
            print_debug(f"OK: {action.capitalize()}ed account for user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: lock_account({username}) - {E}")
            return False
    def set_admin_status(self, username, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to change admin state for user {username} to {should_be_admin}, but DISARMED")
            return False
        try:
            if should_be_admin:
                res = run_bash(f"pw groupmod {self.admingrpname} -m {shlex.quote(username)}")
            else:
                res = run_bash(f"pw groupmod {self.admingrpname} -d {shlex.quote(username)}")
            if (res.returncode != 0) and should_be_admin:
                raise Exception("Admin status update failed")
            print_debug(f"OK: Updated admin status for {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: set_admin_status({username}) - {E}")
            return False
    def delete_user(self, username):
        if DISARM:
            print_debug(f"OK: Attempted to delete user {username}, but DISARMED")
            return False
        try:
            result = run_bash(f"pw userdel {shlex.quote(username)} -r")
            if result.returncode != 0:
                raise Exception(f"pw userdel failed - {result.stderr.strip()}")
            print_debug(f"OK: Deleted user {username}")
            return True
        except Exception as E:
            print_debug(f"ERROR: delete_user({username}) - {E}")
            return False
    def create_user(self, username, password, should_be_admin):
        if DISARM:
            print_debug(f"OK: Attempted to create user {username} but password 'REDACTED' and admin status {should_be_admin}, but DISARMED")
            return False
        try:
            create_cmd = f"echo {shlex.quote(password)} | pw useradd {shlex.quote(username)} -m -s /bin/sh -h 0"
            result = run_bash(create_cmd)
            if result.returncode != 0:
                raise Exception(f"pw useradd failed - {result.stderr.strip()}")
            print_debug(f"OK: Created regular user {username}")
            if should_be_admin:
                if not self.set_admin_status(username, True):
                    raise Exception("Initial admin promotion failed")
            return True
        except Exception as E:
            print_debug(f"ERROR: create_user({username}) - {E}")
            return False
def main_logic(provider):
    users = provider.get_all_users()
    send_message(f"agent/beacon/{AGENT_TYPE}",True,True,str(users))
    try:
        while True:
            try:
                waiting_command = send_message(f"agent/get_task",True,True,"")
                print_debug(f"main_logic: received task msg {waiting_command}")
                if not waiting_command: 
                    break
                if waiting_command == "no pending tasks":
                    break
                data = json.loads(waiting_command)
                task_id = data.get('task_id')
                task_command = data.get('task')
                local_index = data.get('local_index')
                parts = task_command.split(" ")
                status = False
                if parts[0] == "change_password":
                    status = provider.change_password(parts[1],parts[2])
                elif parts[0] == "lock_account":
                    boolEval = parts[2].strip().lower() == 'true'
                    status = provider.lock_account(parts[1],boolEval)
                elif parts[0] == "set_admin_status":
                    boolEval = parts[2].strip().lower() == 'true'
                    status = provider.set_admin_status(parts[1],boolEval)
                elif parts[0] == "delete_user":
                    status = provider.delete_user(parts[1])
                elif parts[0] == "create_user":
                    boolEval = parts[3].strip().lower() == 'true'
                    status = provider.create_user(parts[1],parts[2],boolEval)
                else:
                    print_debug(f"WARNING: main_logic - cmd parts[0] '{parts[0]}' does not match any known command")
                    status = False
                send_message(f"agent/set_task_result",True,True,json.dumps({"task_id": task_id, "result": str(status).lower()}, separators=(',', ':')))
            except Exception as E:
                print_debug(f"ERROR: unexpected error in main_logic iteration: {E}")
    except Exception as E:
        print_debug(f"ERROR: unexpected error in main_logic: {E}")
    return
def signal_handler(sig, frame):
    print_debug("Service stopping due to receiving signal handler")
    sys.exit(0)
def main(stop_event=None):
    global PAUSED
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    send_message(f"agent/beacon/{AGENT_TYPE}",True,True,f"Register")
    print_debug(f"main(): System details - {get_system_details()}")
    try:
        provider = get_user_provider()
    except Exception as e:
        print_debug(f"CRITICAL: Failed to initialize User Management Provider: {e}")
        sys.exit(1)
    while True:
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
                send_message(f"agent/beacon/{AGENT_TYPE}",False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message(f"agent/beacon/{AGENT_TYPE}",True,True,f"Agent moved into ACTIVE status (from PAUSE)")
        if not PAUSED:
            main_logic(provider)
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")
        else:
            if not suppressed_send:
                send_message(f"agent/beacon/{AGENT_TYPE}",True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        time.sleep(SLEEPTIME)
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()