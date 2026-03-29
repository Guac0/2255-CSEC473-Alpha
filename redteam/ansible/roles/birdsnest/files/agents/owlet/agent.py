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
try:
    import win32evtlog
    WINDOWS_LIBS_LOADED = True
except ImportError:
    WINDOWS_LIBS_LOADED = False
CONFIG_DEFAULTS = {
    "AGENT_NAME": "ssh",
    "AUTH_TOKEN": "testtoken",
    "AUTH_LOG_PATH": "",
    "AUTH_PARSER": "",
    "SLEEPTIME": 60,
    "SERVER_URL": "https://127.0.0.1:8000/",
    "SERVER_TIMEOUT": 5,
    "DEBUG_PRINT": True,
    "LOGFILE": "log.txt",
    "STATUSFILE": "status.txt",
    "STATE_FILE": "state.json",
    "AGENT_TYPE": "owlet"
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
AUTH_LOG_PATH = CONFIG["AUTH_LOG_PATH"]
AUTH_PARSER = CONFIG["AUTH_PARSER"]
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
                print_debug(f"Stderr: {result.stderr.strip()}")
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
def get_native_parser():
    if os.path.exists("/etc/debian_version"):
        return DebianAuthParser, "/var/log/auth.log", JournalAuthWatcher
    elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/rocky-release"):
        return RedHatParser, "/var/log/secure", JournalAuthWatcher
    elif os.path.exists("/etc/alpine-release"):
        return AlpineParser, "/var/log/messages", AuthWatcher
    elif os.uname().sysname == "FreeBSD":
        return FreeBSDParser, "/var/log/auth.log", AuthWatcher
    elif "windows" in platform.system().lower():
        if not WINDOWS_LIBS_LOADED:
            print_debug("CRITICAL: Windows detected but pywin32 not installed.")
            return None, None, None
        return WindowsAuthParser, "N/A", WindowsAuthWatcher
    else:
        return DebianAuthParser, "/var/log/auth.log", AuthWatcher
class BaseParser:
    def parse_line(self, line):
        raise NotImplementedError("Each parser must implement parse_line")
    TS_WRAPPER = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(.*)'
    )
    def _parse_timestamp(self, ts_str):
        now = datetime.now()
        if 'T' in ts_str: 
            try:
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
            except ValueError: pass
        try: 
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=now.year)
            if dt > now + timedelta(days=1): dt = dt.replace(year=now.year - 1)
            return dt.timestamp()
        except ValueError: pass
        return None
    def _format_record(self, sig_type, match, epoch_or_line):
        if isinstance(epoch_or_line, (int, float)):
            epoch = epoch_or_line
        else:
            epoch = int(time.time())
        groups = match.groupdict()
        user = groups.get('user', 'unknown')
        ip = groups.get('ip', '127.0.0.1')
        res = {
            "timestamp": epoch,
            "user": user,
            "srcip": ip,
            "login_type": sig_type,
            "successful": True  
        }
        if 'status' in groups:
            status_val = groups['status'].lower()
            res["successful"] = any(x in status_val for x in ["accept", "success", "open", "audit success"])
        if sig_type == "ssh_invalid":
            res["successful"] = False
        if 'src_user' in groups:
            src = groups.get('src_user', 'unknown')
            prefix = sig_type.split('_')[0] 
            res["login_type"] = f"{prefix}({src}->{user})"
        if 'domain' in groups and groups['domain'] not in ['NT AUTHORITY', '']:
            res["user"] = f"{groups['domain']}\\{user}"
        return res
    def __repr__(self):
        return f"NotImplemented Parser"
class DebianAuthParser(BaseParser):
    def __init__(self):
        self.signatures = [
            {
                "type": "ssh_auth",
                "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"),
            },
            {
                "type": "sudo_elevation",
                "regex": re.compile(r"sudo:\s+(?P<src_user>\S+) : TTY=.* ; USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)"),
            },
            {
                "type": "ssh_invalid",
                "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
            }
        ]
        self.ts_wrapper_pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(.*)'
        )
    def _parse_timestamp(self, ts_str):
        now = datetime.now()
        if 'T' in ts_str:
            try:
                clean_ts = ts_str.replace('Z', '+00:00')
                dt = datetime.fromisoformat(clean_ts)
                return dt.timestamp()
            except ValueError:
                pass
        try:
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            dt = dt.replace(year=now.year)
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
            return dt.timestamp()
        except ValueError:
            pass
        return None
    def parse_line(self, line):
        match = self.ts_wrapper_pattern.match(line)
        if not match:
            return None
        ts_str = match.group(1)
        remaining_content = match.group(2)
        epoch = self._parse_timestamp(ts_str)
        if epoch is None:
            return None
        for sig in self.signatures:
            attr_match = sig['regex'].search(remaining_content)
            if attr_match:
                return self._format_record(sig['type'], attr_match, epoch)
        return None
    def __repr__(self):
        return f"DebianAuthParser"
class RedHatParser(BaseParser):
    def __init__(self):
        self.signatures = [
            {"type": "ssh_auth", "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) \S+ for (?P<user>\S+) from (?P<ip>\S+)")},
            {"type": "ssh_invalid", "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)")}
        ]
    def parse_line(self, line):
        m = self.TS_WRAPPER.match(line)
        if not m: return None
        epoch = self._parse_timestamp(m.group(1))
        if not epoch: return None
        content = m.group(2)
        for sig in self.signatures:
            match = sig['regex'].search(content)
            if match:
                return self._format_record(sig['type'], match, epoch)
        return None
    def __repr__(self):
        return f"RedHatParser"
class AlpineParser(BaseParser):
    def __init__(self):
        self.signatures = [
            {"type": "ssh_auth", "regex": re.compile(r"(?:auth\.info )?sshd\[\d+\]: (?P<status>Accepted|Failed) \S+ for (?P<user>\S+) from (?P<ip>\S+)")},
            {"type": "sudo_elevation", "regex": re.compile(r"(?:auth\.info )?sudo:\s+(?P<src_user>\S+) :.*USER=(?P<user>\S+) ; COMMAND=(?P<cmd>.*)")}
        ]
    def parse_line(self, line):
        m = self.TS_WRAPPER.match(line)
        if not m: return None
        epoch = self._parse_timestamp(m.group(1))
        if not epoch: return None
        content = m.group(2)
        for sig in self.signatures:
            match = sig['regex'].search(content)
            if match:
                return self._format_record(sig['type'], match, epoch)
        return None
    def __repr__(self):
        return f"AlpineParser"
class FreeBSDParser(BaseParser):
    def __init__(self):
        self.signatures = [
            {
                "type": "ssh_auth", 
                "regex": re.compile(r"sshd\[\d+\]: (?P<status>Accepted|Failed) (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port")
            },
            {
                "type": "su_elevation", 
                "regex": re.compile(r"su\[\d+\]: (?P<src_user>\S+) to (?P<user>\S+) on (?P<tty>\S+)")
            },
            {
                "type": "console_fail", 
                "regex": re.compile(r"login: FAIL on (?P<tty>\S+) for (?P<user>\S+), password incorrect")
            },
            {
                "type": "ssh_invalid",
                "regex": re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+)")
            }
        ]
    def parse_line(self, line):
        match = self.TS_WRAPPER.match(line)
        if not match:
            return None
        ts_str = match.group(1)
        remaining_content = match.group(2)
        epoch = self._parse_timestamp(ts_str)
        if epoch is None:
            return None
        for sig in self.signatures:
            attr_match = sig['regex'].search(remaining_content)
            if attr_match:
                return self._format_record(sig['type'], attr_match, epoch)
        return None
    def __repr__(self):
        return f"FreeBSDParser"
class WindowsAuthParser(BaseParser):
    def __init__(self):
        self.log_type = "Security"
        self.event_ids = {4624: True, 4625: False}
        self.ignored_users = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"]
        self.interesting_logon_types = ["2", "10", "11"]
    def parse_event(self, event):
        event_id = event.EventID & 0xFFFF
        if event_id not in self.event_ids:
            return None
        inserts = event.StringInserts
        if not inserts or len(inserts) < 19:
            return None
        try:
            user = inserts[5]
            domain = inserts[6]
            logon_type = inserts[8]
            ip = inserts[18]
            if user.upper() in self.ignored_users or user.endswith('$'):
                return None
            if event_id == 4624 and logon_type not in self.interesting_logon_types:
                return None
            if ip in ["-", "::1", "127.0.0.1"]:
                ip = "127.0.0.1"
            class MockMatch:
                def __init__(self, data): self.data = data
                def groupdict(self): return self.data
            mock_match = MockMatch({
                "user": user,
                "domain": domain,
                "ip": ip,
                "logon_type_code": logon_type, 
                "status": "success" if self.event_ids[event_id] else "failed"
            })
            epoch = int(event.TimeGenerated.timestamp())
            return self._format_record("win_auth", mock_match, epoch)
        except Exception:
            return None
    def __repr__(self):
        return "WindowsAuthParser"
class AlertThrottler:
    def __init__(self, threshold=10, window=60, max_entries=1000):
        self.threshold = threshold
        self.window = window
        self.max_entries = max_entries  
        self.history = {}
        self.suppressed = set()
        self.last_cleanup = time.time()
    def _cleanup_all(self):
        now = time.time()
        if now - self.last_cleanup >= 600:
            expired_ips = []
            for ip, timestamps in self.history.items():
                self.history[ip] = [t for t in timestamps if now - t < self.window]
                if not self.history[ip]:
                    expired_ips.append(ip)
            for ip in expired_ips:
                self._purge_ip(ip)
            self.last_cleanup = now
        if len(self.history) > self.max_entries:
            sorted_ips = sorted(self.history.keys(), key=lambda x: self.history[x][-1])
            excess_count = len(self.history) - self.max_entries
            for i in range(excess_count):
                self._purge_ip(sorted_ips[i])
    def _purge_ip(self, ip):
        if ip in self.history:
            del self.history[ip]
        if ip in self.suppressed:
            self.suppressed.remove(ip)
    def should_throttle(self, ip):
        now = time.time()
        self._cleanup_all()
        if ip not in self.history:
            self.history[ip] = []
        self.history[ip] = [t for t in self.history[ip] if now - t < self.window]
        currently_suppressed = ip in self.suppressed
        attempt_count = len(self.history[ip])
        if attempt_count >= self.threshold and not currently_suppressed:
            self.suppressed.add(ip)
            return "START_THROTTLE"
        if currently_suppressed:
            if attempt_count < (self.threshold / 2):
                self.suppressed.remove(ip)
                self.history[ip].append(now)
                return "END_THROTTLE"
            self.history[ip].append(now)
            return "SILENCE"
        self.history[ip].append(now)
        return "PROCEED"
class AuthWatcher:
    def __init__(self, parser, auth_log):
        self.parser = parser
        self.auth_log = auth_log
        self.config = self.fetch_config()
        self.last_scan_time = self.load_state()
        self.throttler = AlertThrottler(threshold=5, window=60)
        self.seen_signatures = set()
    def fetch_config(self):
        base_config = {
            "users": {"legitimate": [], "malicious": []},
            "ips": {"legitimate": [], "malicious": []}
        }
        got_config = send_message("agent/list_authconfig_agent")
        if got_config:
            base_config.update(json.loads(got_config))
        else:
            print_debug(f"Error fetching entity lists")
        global_settings = send_message("agent/list_authconfigglobal")
        if global_settings:
            try:
                global_settings = json.loads(global_settings)
                for key, val in global_settings.items():
                    if isinstance(val, str):
                        if val.lower() == "true": val = True
                        elif val.lower() == "false": val = False
                    base_config[key] = val
            except Exception as E:
                print_debug(f"Error applying global config, using default fallbacks. error: {E}")
                base_config.setdefault("strict_user", False)
                base_config.setdefault("strict_ip", False)
                base_config.setdefault("create_incident", False)
                base_config.setdefault("log_attempt_successful", True)
        else:
            print_debug(f"Error fetching global config, using default fallbacks")
            base_config.setdefault("strict_user", False)
            base_config.setdefault("strict_ip", False)
            base_config.setdefault("create_incident", False)
            base_config.setdefault("log_attempt_successful", True)
        print_debug(f"fetch_config(): returning config - {base_config}")
        return base_config
    def load_state(self):
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                return json.load(f).get("last_scan", time.time())
        return int(time.time())
    def save_state(self, timestamp):
        temp_file = f"{STATE_FILE}.tmp"
        try:
            with open(temp_file, 'w') as f:
                json.dump({"last_scan": int(timestamp)}, f)
                f.flush()
                os.fsync(f.fileno()) 
            os.replace(temp_file, STATE_FILE) 
        except Exception as e:
            print_debug(f"save_state(): Failed to save state: {e}")
    def analyze_log(self):
        self.temp_signatures = set()
        new_last_scan = self.load_state()
        self.last_scan_time = new_last_scan
        sent_msg = False
        records_to_process = []
        if not os.path.exists(self.auth_log):
            return sent_msg
        file_size = os.path.getsize(self.auth_log)
        if file_size == 0:
            return sent_msg
        with open(self.auth_log, 'rb') as f:
            f.seek(0, os.SEEK_END)
            pointer = f.tell()
            buffer = b""
            chunk_size = 4096
            reached_cutoff = False
            while pointer > 0 and not reached_cutoff:
                if pointer - chunk_size > 0:
                    pointer -= chunk_size
                    f.seek(pointer)
                    chunk = f.read(chunk_size)
                else:
                    f.seek(0)
                    chunk = f.read(pointer)
                    pointer = 0
                chunk += buffer
                lines = chunk.splitlines()
                if pointer > 0:
                    buffer = lines.pop(0)
                else:
                    buffer = b""
                for line in reversed(lines):
                    decoded_line = line.decode('utf-8', errors='replace')
                    record = self.parser.parse_line(decoded_line)
                    if not record: continue
                    import hashlib
                    line_sig = hashlib.md5(line).hexdigest()
                    if record['timestamp'] < self.last_scan_time:
                        reached_cutoff = True
                        break
                    if record['timestamp'] == self.last_scan_time:
                        if line_sig in self.seen_signatures:
                            continue
                    records_to_process.append(record)
                    if record['timestamp'] > new_last_scan:
                        new_last_scan = record['timestamp']
                        self.temp_signatures = {line_sig}
                    elif record['timestamp'] == new_last_scan:
                        self.temp_signatures.add(line_sig)
            if not reached_cutoff and buffer:
                decoded_line = buffer.decode('utf-8', errors='replace')
                record = self.parser.parse_line(decoded_line)
                if record and record['timestamp'] > self.last_scan_time:
                    records_to_process.append(record)
                    if record['timestamp'] > new_last_scan:
                        new_last_scan = record['timestamp']
        records_to_process.reverse()
        for record in records_to_process:
            if self.evaluate_threat(record):
                sent_msg = True
        self.seen_signatures = self.temp_signatures
        self.save_state(new_last_scan)
        return sent_msg
    def evaluate_threat(self, auth):
        ip = auth.get('srcip', '127.0.0.1')
        user = auth.get('user', 'unknown')
        throttle_status = self.throttler.should_throttle(ip)
        if throttle_status == "SILENCE":
            print_debug(f"evaluate_threat(): IP {ip} is silenced. Ignoring log.")
            return False
        strict_ip = self.config.get('strict_ip', False)
        strict_user = self.config.get('strict_user', False)
        is_mal_user = user in self.config['users']['malicious'] if not strict_user else user not in self.config['users']['legitimate']
        is_mal_ip = ip in self.config['ips']['malicious'] if not strict_ip else ip not in self.config['ips']['legitimate']
        is_malicious = is_mal_user or is_mal_ip
        old_status = not is_malicious
        new_status = not (is_malicious and auth['successful'])
        msg = None
        if throttle_status == "START_THROTTLE":
            msg = f"FLOOD CONTROL: IP {ip} is being throttled for excessive login attempts."
            old_status = False  
        elif throttle_status == "END_THROTTLE":
            msg = f"FLOOD CONTROL: IP {ip} is no longer being throttled."
            old_status = True   
            new_status = True
        elif is_mal_user and is_mal_ip:
            msg = f"SECURITY ALERT: Known malicious user {user} from malicious IP {ip}"
        elif is_mal_user:
            msg = f"SECURITY ALERT: Malicious user access: {user}"
        elif is_mal_ip:
            msg = f"SECURITY ALERT: Access from malicious IP: {ip}"
        if msg:
            print_debug(f"evaluate_threat(): Sending beacon - {msg}")
            send_message("agent/beacon/owlet", old_status, new_status, msg, authInfo=auth)
            return True
        return False
class JournalAuthWatcher(AuthWatcher):
    def get_journal_logs(self, since_timestamp):
        since_str = datetime.fromtimestamp(since_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        command_str = f"journalctl SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 --since {since_str} --output=short-iso --no-pager"
        result = run_bash(command_str, noisy=False)
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            print_debug(f"JournalAuthWatcher: Failed to query journalctl (Code {result.returncode}): {result.stderr.strip()}")
            return []
    def analyze_log(self):
        if os.path.exists(self.auth_log) and os.path.getsize(self.auth_log) > 0:
            return super().analyze_log()
        print_debug(f"JournalAuthWatcher: {self.auth_log} not found. Using journalctl fallback.")
        self.last_scan_time = self.load_state()
        lines = self.get_journal_logs(self.last_scan_time)
        records_to_process = []
        new_last_scan = self.last_scan_time
        sent_msg = False
        for line in lines:
            record = self.parser.parse_line(line)
            if record and record['timestamp'] > self.last_scan_time:
                records_to_process.append(record)
                if record['timestamp'] > new_last_scan:
                    new_last_scan = record['timestamp']
        for record in records_to_process:
            if self.evaluate_threat(record):
                sent_msg = True
        self.save_state(new_last_scan)
        return sent_msg
if WINDOWS_LIBS_LOADED:
    class WindowsAuthWatcher(AuthWatcher):
        def load_state(self):
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    state = json.load(f)
                    return state.get("last_record", 0), state.get("last_scan", time.time())
            return 0, int(time.time())
        def analyze_log(self):
            last_record, last_timestamp = self.load_state()
            server = 'localhost'
            handle = win32evtlog.OpenEventLog(server, self.parser.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            sent_msg = False
            records_to_process = []
            reached_cutoff = False
            new_last_scan = self.last_scan_time
            while not reached_cutoff:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                for event in events:
                    if event.RecordNumber <= last_record:
                        reached_cutoff = True
                        break
                    record = self.parser.parse_event(event)
                    if record:
                        records_to_process.append(record)
                        if event.RecordNumber > new_last_record:
                            new_last_record = event.RecordNumber
                        if reached_cutoff: break
            records_to_process.reverse()
            for record in records_to_process:
                if self.evaluate_threat(record):
                    sent_msg = True
            self.save_state(new_last_scan)
            win32evtlog.CloseEventLog(handle)
            return sent_msg
else:
    class WindowsAuthWatcher:
        def __init__(self, *args, **kwargs):
            pass
        def analyze_log(self):
            return False
def signal_handler(sig, frame):
    print_debug("Service stopping due to receiving signal handler")
    sys.exit(0)
def main(stop_event=None):
    global PAUSED
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    send_message("agent/beacon/owlet",True,True,f"Register")
    print_debug(f"main(): System details - {get_system_details()}")
    PARSER_MAP = {
        "debian": DebianAuthParser,
        "ubuntu": DebianAuthParser,
        "rhel": RedHatParser,
        "rocky": RedHatParser,
        "alpine": AlpineParser,
        "freebsd": FreeBSDParser
    }
    parser, log_path, watcherObj = get_native_parser()
    if AUTH_LOG_PATH:
        log_path = AUTH_LOG_PATH
    if AUTH_PARSER:
        parser = PARSER_MAP.get(AUTH_PARSER.lower(), parser)
    watcher = watcherObj(parser(),log_path)
    print_debug(f"Selected parser {parser} and log path {log_path}")
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
                send_message("agent/beacon/owlet",False,False,f"Agent moved into PAUSE status for {int(pausedEpochLocal - time.time())} seconds")
            else:
                send_message("agent/beacon/owlet",True,True,f"Agent moved into ACTIVE status (from PAUSE)")
        if not PAUSED:
            watcher.config = watcher.fetch_config()
            sent_msg = watcher.analyze_log()
            if not sent_msg:
                send_message("agent/beacon/owlet",True,True,"all good")
            print_debug(f"main(): sleeping for {SLEEPTIME} seconds")
            print_debug(f"")
        else:
            if not suppressed_send:
                send_message("agent/beacon/owlet",True,False,f"Agent still in PAUSE status for {int(pausedEpochLocal - time.time())} seconds remaining")
        time.sleep(SLEEPTIME)
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()