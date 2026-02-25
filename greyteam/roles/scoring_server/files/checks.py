import subprocess
import random
from server import (
    Service, ScoringUser, ScoringCriteria, Host, db
)
import paramiko
from winrm.protocol import Protocol
import smbclient
from ftplib import FTP
import time
from datetime import datetime
import socket
import re
import base64

OFFLINE_TEAM_ID = 1
MAX_ERROR_LEN = 200
DOMAIN = ""
DOMAIN_ADMINS = []
DOMAIN_USERS = []
LOCAL_ADMINS = []
LOCAL_USERS = []
ALL_DOMAIN = DOMAIN_ADMINS + DOMAIN_USERS
ALL_LOCAL = LOCAL_ADMINS + LOCAL_USERS
ALL_ADMINS = DOMAIN_ADMINS + LOCAL_ADMINS
ALL_USERS = DOMAIN_USERS + LOCAL_USERS
ALL_ALL = DOMAIN_ADMINS + DOMAIN_USERS + LOCAL_ADMINS + LOCAL_USERS

class Criterion:
    team:int
    loc:str
    content:str

    def __init__(self, criterion:ScoringCriteria) -> None:
        try:
            self.team = criterion.team_id
            self.loc = criterion.location
            self.content = criterion.content
        except Exception as e:
            raise e

class Check:
    '''
    Template for all checks.
    
    :var check_id: the ID of the service that we are conducting the check for
    :vartype check_id: int
    :var host: the IP of the host that we are conducting the check on
    :vartype host: str
    :var criteria: a list of criteria for the check
    '''
    check_id:int
    host:str
    host_ip:int
    criteria:list[Criterion]

    def __init__(self, check:Service) -> None:
        try:
            self.check_id = check.id
            self.host = check.host_id
            self.host_ip = Host.query.filter_by(id = self.host).first().ip
            self.criteria = [Criterion(criterion) for criterion in ScoringCriteria.query.filter_by(service_id = self.check_id)]
        except Exception as e:
            raise e

    def update_criteria(self) -> None:
        '''
        Updates the criteria from the database
        '''
        try:
            self.criteria = [Criterion(criterion) for criterion in ScoringCriteria.query.filter_by(service_id = self.check_id)]
        except Exception as e:
            raise e

    def check () -> tuple[int, str]:
        '''
        Performs a check.
        
        :return: a tuple containing the integer identifier of the appropriate team and a success/failure message
        :rtype: tuple[int,str]
        '''

        return (OFFLINE_TEAM_ID, "Check class")

class Http (Check):

    def __init__(self, check: Service) -> None:
        super().__init__(check)        

    def check (self):
        err = []
        for criterion in self.criteria:
            try:
                res = subprocess.run(
                    ["curl", f"{self.host_ip}:{criterion.loc}"],
                    capture_output=True,
                    text=True
                )
                
                # Check succeeded
                if res.returncode == 0 and criterion.content in res.stdout:
                    return (criterion.team, f"Found expected content")
                # Command failed
                elif res.returncode != 0:
                    err.insert(OFFLINE_TEAM_ID, res.stderr)
                # Incorrect output
                elif criterion.content not in res.stdout:
                    err.append(f"Could not find expected content")
            except Exception as E:
                err.append(f"{str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])

class Mysql (Check):
    users:list[tuple[str,str]]

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter(ScoringUser.host_id == self.host)

        self.users = []
        for user in users:
            if user.username in ALL_LOCAL:
                self.users.append((user.username, user.password))
    
    def check (self):
        user = random.choice(self.users)
        
        err = []
        for criterion in self.criteria:
            try:
                res = subprocess.run(
                    ["mysql", "-h", self.host_ip,
                    "-u", f"{user[0]}",
                    f"-p{user[1]}",
                    "-e", criterion.loc],
                    capture_output=True,
                    text=True
                )
                
                # Check succeeded
                if res.returncode == 0 and criterion.content in res.stdout:
                    return (criterion.team, f"Found expected content")
                # Command failed
                elif res.returncode != 0:
                    err.insert(OFFLINE_TEAM_ID, res.stderr)
                # Incorrect output
                elif criterion.content not in res.stdout:
                    err.append(f"Could not find expected content")
            except Exception as E:
                err.append(f"{user[0]} - {str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])

class Dns (Check):
    def __init__(self, check: Service) -> None:
        super().__init__(check)

    def check (self):        
        err = []
        for criterion in self.criteria:
            try:
                res = subprocess.run(
                    ["nslookup", criterion.loc, self.host_ip],
                    capture_output=True,
                    text=True
                )
                
                # Check succeeded
                if res.returncode == 0 and criterion.content in res.stdout:
                    return (criterion.team, f"Found expected content")
                # Command failed
                elif res.returncode != 0:
                    err.insert(OFFLINE_TEAM_ID, res.stderr)
                # Incorrect output
                elif criterion.content not in res.stdout:
                    err.append(f"Could not find expected content")
            except Exception as E:
                err.append(f"{str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])

class Smb (Check):
    users:list[tuple[str,str]]

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter(ScoringUser.host_id == self.host)

        self.users = []
        for user in users:
            if user.username in ALL_LOCAL:
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                smbclient.register_session(server="Appleloosa", username=user[0], password=user[1])

                if (smbclient.path.exists(criterion.loc)):
                    with smbclient.open_file(criterion.loc, mode="r") as fd:
                        res = fd.read()

                        if criterion.content in res:
                            return (criterion.team, f"Found expected content")
                        else:
                            err.append(f"Could not find expected content")
                else:
                    err.insert(OFFLINE_TEAM_ID, f"Scoring file does not exist")

            except Exception as E:
                err.append(f"{user[0]} - {str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])

class Ftp (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter(ScoringUser.host_id == self.host)

        self.users = []
        for user in users:
            if user.username in ALL_LOCAL:
                self.users.append((user.username, user.password))

    def check(self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            location = criterion.loc
            try:
                res = []
                with FTP(self.host_ip) as ftp:
                    ftp.login(user[0], user[1])
                    ftp.retrlines(f'RETR {criterion.loc}', res.append)

                if criterion.content in "\n".join(res).strip():
                    return (criterion.team, f"Found expected content")
                else:
                    err.append(f"Could not find expected content")

            except Exception as E:
                err.append(f"{user[0]} - {str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])

class Mssql (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        #users:list[ScoringUser] = ScoringUser.query.filter(ScoringUser.host_id == self.host)
        users = db.session.query(ScoringUser).join(Host).filter(
            Host.hostname == "canterlot"
        ).all()

        self.users = []
        for user in users:
            if user.username in DOMAIN_ADMINS:
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                username = user[0]
                password = user[1]
                #target_host = f"{self.host_ip},1433"
                target_host = f"manehatten.mlp.local,1433" # TODO hardcoded!
                db_name = "db"

                # Pipe the password to kinit using the input parameter
                kinit_proc = subprocess.run(
                    ['kinit', f"{username}@{DOMAIN.upper()}"],
                    input=password.encode(),
                    capture_output=True,
                    check=True
                )

                if kinit_proc.returncode != 0:
                    err.append(kinit_proc.stderr)
                    continue

                # Execute sqlcmd using the Kerberos ticket (-E)
                # -s"," sets comma as separator, -W removes trailing spaces, -h-1 removes headers
                res = subprocess.run(
                    [
                        # /opt/mssql-tools18/bin/sqlcmd -E -C -S manehatten.mlp.local,1433 -d "db" -Q "SELECT E.Virtue AS [The Element], C.Name AS [Bearer], C.Species AS [Species], C.LoreTitle AS [Known As], L.PlaceName AS [Resides In] FROM [dbo].[Elements] E JOIN [dbo].[Characters] C ON E.BearerID = C.CharID JOIN [dbo].[Locations] L ON C.HomeLocationID = L.LocationID ORDER BY C.Name;" -s , -W -h-1
                        # /opt/mssql-tools18/bin/sqlcmd -E -C -S manehatten.mlp.local,1433 -d "db" -Q "WITH ElementSummary AS ( SELECT C.Name + '(' + E.Virtue + ')' AS BearerInfo FROM [dbo].[Elements] E JOIN [dbo].[Characters] C ON E.BearerID = C.CharID JOIN [dbo].[Locations] L ON C.HomeLocationID = L.LocationID ) SELECT STRING_AGG(BearerInfo, ', ') WITHIN GROUP (ORDER BY BearerInfo ASC) AS FlatResult FROM ElementSummary;" -s , -W -h-1
                        '/opt/mssql-tools18/bin/sqlcmd', '-E', '-C', 
                        '-S', target_host, 
                        '-d', db_name, 
                        '-Q', criterion.loc, 
                        '-s', ',', '-W', '-h-1'
                    ],
                    capture_output=True,
                    text=True
                )

                lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
                final_string = "".join(lines)

                # Check succeeded
                if res.returncode == 0 and criterion.content in final_string:
                    return (criterion.team, f"Found expected content")
                # Command failed
                elif res.returncode != 0:
                    err.insert(OFFLINE_TEAM_ID, f"{user[0]} - {res.stderr}")
                # Incorrect output
                elif criterion.content not in final_string:
                    err.append(f"Could not find expected content")

            except Exception as E:
                err.append(f"{user[0]} - {str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])
    
class Cups (Check):
    def __init__ (self, check: Service) -> None:
        super().__init__(check)

    def check (self):
        err = []
        for criterion in self.criteria:
            try:
                start_time = datetime.now().replace(year=1900, month=1, day=1)

                #lp -h 10.10.0.5 -d printer testfile.pdf
                res = subprocess.run(
                    ["lp", "-h", self.host_ip,
                     "-d", "printer",
                     "cadance.pdf"],
                    capture_output=True,
                    text=True
                )

                time.sleep(5)

                # Print command didn't go through
                if res.returncode != 0:
                    err.insert(OFFLINE_TEAM_ID, res.stderr)
                    continue

                # SSH into the box to check if print job went through
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(self.host_ip, username="greyteam", password="ponyuploc0!")

                # Check successful print jobs                
                stdin, stdout, stderr = client.exec_command("sudo ls -ot --time-style=+%X /home/cadance/print | head -n 2")
                if stdout.channel.recv_exit_status() != 0:
                    err.append("Could not access print output directory")
                    continue
                string = stdout.read().decode()

                # Get the time the print was submitted
                pattern = r"\d{2}:\d{2}:\d{2} (AM|PM)"
                try:
                    res = re.search(pattern, string).group(0)
                except Exception as e:
                    err.append("Print job did not output file")
                    continue
                time_elapsed = start_time - datetime.strptime(res, '%I:%M:%S %p')
                if time_elapsed.total_seconds() < 0:
                    err.append("Print job did not output file")
                    continue

                # Get filename
                filename = string.split(" ")[-1]

                # Get hash
                stdin, stdout, stderr = client.exec_command(f"sudo sha256sum /home/cadance/print/{filename}")
                if stdout.channel.recv_exit_status() != 0:
                    err.append("Could not generate hash for print file")
                    continue
                print_hash = stdout.read().decode()

                # Clean up our tracks, just 'cause
                client.exec_command(f"sudo rm /home/cadance/print/{filename}")

                # Evaluate hash
                if criterion.content in print_hash:
                    return (criterion.team, "Found expected content")
                # Incorrect output
                elif criterion.content not in print_hash:
                    err.append(f"Could not find expected content")
            except Exception as E:
                err.append(f"{str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])

class Irc (Check):
    def __init__(self, check: Service) -> None:
        super().__init__(check)

    def recv_until(self, sock:socket.socket, expected_strings, timeout=5):
        """Receive data until one of the expected_strings appears or timeout."""
        sock.settimeout(timeout)
        buffer = ""
        start_time = time.time()
        while True:
            try:
                chunk = sock.recv(4096).decode(errors='ignore')
                buffer += chunk
            except socket.timeout:
                pass
            if any(s in buffer for s in expected_strings):
                return buffer
            if time.time() - start_time > timeout:
                break
        return buffer

    def check(self) -> tuple[int, str]:
        try:
            sock = socket.create_connection((str(self.host_ip), 6667), timeout = 5)
        except Exception as e:
            return (OFFLINE_TEAM_ID, f"Service not available: {e}")

        try:
            sock.sendall(("NICK scorebot\r\n").encode())
            sock.sendall(("USER scorebot 0 * :Score Bot\r\n").encode())

            response = self.recv_until(sock, ["001"], timeout=10)
            if "001" not in response:
                return (OFFLINE_TEAM_ID, f"Handshake failed: Did not receive welcome message")
            
            err = []
            for criterion in self.criteria:
                sock.sendall((f"JOIN {criterion.loc}\r\n").encode())
                response = self.recv_until(sock, [f"JOIN :{criterion.loc}", "ERROR"])
                if f"JOIN :{criterion.loc}" not in response:
                    err.append(f"Channel join failed: {criterion.loc}")
                    continue

                # Test send
                sock.sendall((f"PRIVMSG {criterion.loc} :scorecheck\r\n").encode())
                msg_response = self.recv_until(sock, [criterion.content, "ERROR"])
                if "ERROR" in msg_response.upper():
                    err.append("Message send failed")
                    continue
                
                return (criterion.team, "Found expected content")
        finally:
            sock.close()
        
        return (OFFLINE_TEAM_ID, err[0])

class Workstation_linux (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter(ScoringUser.host_id == self.host)

        self.users = []
        for user in users:
            if user.username in ALL_LOCAL:
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                username = user[0]
                password = user[1]
                filepath = criterion.loc
                expected_hash = criterion.content
                
                # Initialize SSH Client
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(self.host_ip, username=username, password=password)

                # 1. Check if executable (the -L flag in the shell ensures we follow symlinks)
                # We use 'test -x' which returns 0 if executable, 1 otherwise
                exec_check_cmd = f"test -x {filepath}"
                stdin, stdout, stderr = client.exec_command(exec_check_cmd)
                is_executable = stdout.channel.recv_exit_status() == 0

                if not is_executable:
                    client.close()
                    err.append(f"File {filepath} is not executable or does not exist")
                    continue

                # 2. Check the File Hash
                # -L follows symlinks for the hash calculation
                hash_cmd = f"sha256sum {filepath} | cut -d' ' -f1"
                stdin, stdout, stderr = client.exec_command(hash_cmd)
                
                actual_hash = stdout.read().decode().strip()
                client.close()

                if actual_hash == expected_hash:
                    return (criterion.team, f"Found expected content")
                else:
                    err.append(f"File {filepath} does not match expected hash")

            except Exception as E:
                err.append(f"{user[0]} - {str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])

class Workstation_windows (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter(ScoringUser.host_id == self.host)

        self.users = []
        for user in users:
            if user.username in ALL_LOCAL:
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                username = user[0]
                password = user[1]
                filepath = criterion.loc
                expected_hash = criterion.content
                
                endpoint = f'http://{self.host_ip}:5985/wsman'
                p = Protocol(
                    endpoint=endpoint,
                    transport='ntlm',
                    username=username,
                    password=password,
                    server_cert_validation='ignore'
                )

                # PowerShell Script:
                # 1. Get-Item -Path follows symlinks/junctions by default.
                # 2. Check if the file has 'Execute' permissions for the current user.
                # 3. Calculate SHA256 hash.

                #$perm = (Get-Acl $item.FullName).Access | Where-Object {{ 
                    #    $_.IdentityReference -eq "{username}" -or $_.IdentityReference -eq "Everyone" 
                    #}} | Where-Object {{ $_.FileSystemRights -match "ExecuteFile|FullControl" }}
                ps_script = f"""
                $path = "{filepath}"
                if (Test-Path $path) {{
                    $item = Get-Item -Path $path
                    
                    $hash = (Get-FileHash $item.FullName -Algorithm SHA256).Hash
                    
                    if ($hash -eq "{expected_hash}") {{
                        Write-Output "Found expected content"
                    }} else {{
                        Write-Output "File does not match expected hash"
                    }}
                }} else {{
                    Write-Output "File does not exist"
                }}
                """
                encoded_ps = base64.b64encode(ps_script.encode('utf-16-le')).decode('utf-8')
                shell_id = p.open_shell()
                #command_id = p.run_command(shell_id, 'powershell', ['-Command', ps_script])
                command_id = p.run_command(shell_id, 'powershell', ['-EncodedCommand', encoded_ps])
                std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
                p.cleanup_command(shell_id, command_id)
                p.close_shell(shell_id)

                output = std_out.decode().strip()
                firstword = output.split(" ")[0].strip()
                if ((firstword != "File") and (firstword != "Found")):
                    raise ValueError(output)
                
                if firstword == "Found":
                    return (criterion.team, f"{output}")
                else:
                    err.append(f"{output}")

            except Exception as E:
                err.append(f"{user[0]} - {str(E)[:MAX_ERROR_LEN]}")
        
        return (OFFLINE_TEAM_ID, err[0])