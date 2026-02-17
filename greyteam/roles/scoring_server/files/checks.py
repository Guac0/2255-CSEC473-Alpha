import subprocess
import random
from server import (
    Service, ScoringUser, ScoringCriteria, Host
)
import paramiko
from winrm.protocol import Protocol
import smbclient
from ftplib import FTP

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

        return (0, "Check class")

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
                    return (criterion.team, f"Found expected content for check {criterion.id}")
                # Command failed
                elif res.returncode != 0:
                    err.insert(0, res.stderr)
                # Incorrect output
                elif criterion.content not in res.stdout:
                    err.append(f"Could not find expected content for check {criterion.id}")
            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])

class Mysql (Check):
    users:list[tuple[str,str]]

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter_by(host_id == self.host)

        for user in users:
            self.users.append((user.username, user.password))
    
    def check (self):
        user = random.choice(self.users)
        
        err = []
        for criterion in self.criteria:
            try:
                res = subprocess.run(
                    ["mysql", "-h", self.host_ip,
                    "-u", f"{user[0]}"
                    "-p", f"{user[1]}",
                    criterion.loc],
                    capture_output=True,
                    text=True
                )
                
                # Check succeeded
                if res.returncode == 0 and criterion.content in res.stdout:
                    return (criterion.team, f"Found expected content for check {criterion.id}")
                # Command failed
                elif res.returncode != 0:
                    err.insert(0, res.stderr)
                # Incorrect output
                elif criterion.content not in res.stdout:
                    err.append(f"Could not find expected content for check {criterion.id}")
            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])

class Dns (Check):
    hosts:list[tuple[str,str]]

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        hosts:list[Host] = Host.query.all()

        for host in hosts:
            self.hosts.append((host.hostname, host.ip))

    def check (self):
        host = random.choice(self.hosts)
        
        err = []
        for criterion in self.criteria:
            try:
                res = subprocess.run(
                    ["nslookup", f"{host[0]}.mlp.local", self.host_ip],
                    capture_output=True,
                    text=True
                )
                
                # Check succeeded
                if res.returncode == 0 and host[1] in res.stdout:
                    return (criterion.team, f"Found expected content for check {criterion.id}")
                # Command failed
                elif res.returncode != 0:
                    err.insert(0, res.stderr)
                # Incorrect output
                elif host[1] not in res.stdout:
                    err.append(f"Could not find expected content for check {criterion.id}")
            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])

class Smb (Check):
    def __init__(self, check: Service) -> None:
        super().__init__(check)

    def check (self):        
        err = []
        for criterion in self.criteria:
            try:
                smbclient.register_session(server="Appleloosa")

                if (smbclient.path.exists(criterion.loc)):
                    with smbclient.open_file(criterion.loc, mode="r") as fd:
                        res = fd.read()

                        if criterion.content in res:
                            return (criterion.team, f"Found expected content for check {criterion.id}")
                        else:
                            err.append(f"Could not find expected content for check {criterion.id}")
                else:
                    err.insert(0, f"Scoring file does not exist")

            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])

class Ftp (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter_by(host_id == self.host)

        for user in users:
            self.users.append((user.username, user.password))

    def check(self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                res = []
                with FTP(self.host_ip) as ftp:
                    ftp.login(user[0], user[1])
                    ftp.retrlines(criterion.loc, res.append)

                if criterion.content in "\n".join(res).strip():
                    return (criterion.team, f"Found expected content for check {criterion.id}")
                else:
                    err.append(f"Could not find expected content for check {criterion.id}")

            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])

class Mssql (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter_by(host_id == self.host)

        for user in users:
            if user in DOMAIN_ADMINS:
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                username = user[0]
                password = user[1]
                target_host = f"{self.host_ip},1433"
                db_name = "db"

                # Pipe the password to kinit using the input parameter
                kinit_proc = subprocess.run(
                    ['kinit', f"{username}@{DOMAIN}"],
                    input=password.encode(),
                    capture_output=True,
                    check=True
                )

                # Execute sqlcmd using the Kerberos ticket (-E)
                # -s"," sets comma as separator, -W removes trailing spaces, -h-1 removes headers
                res = subprocess.run(
                    [
                        '/opt/mssql-tools18/bin/sqlcmd', '-E', '-C', 
                        '-S', target_host, 
                        '-d', db_name, 
                        '-Q', criterion.location, 
                        '-s', ',', '-W', '-h-1'
                    ],
                    capture_output=True,
                    text=True
                )

                # Check succeeded
                if res.returncode == 0 and criterion.content in res.stdout:
                    return (criterion.team, f"Found expected content for check {criterion.id}")
                # Command failed
                elif res.returncode != 0:
                    err.insert(0, res.stderr)
                # Incorrect output
                elif criterion.content not in res.stdout:
                    err.append(f"Could not find expected content for check {criterion.id}")

            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])
    
class Workstation_linux (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter_by(host_id == self.host)

        for user in users:
            if user in ALL_LOCAL:
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                username = user[0]
                password = user[1]
                filepath = criterion.location
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
                    err.append(f"File {filepath} is not executable or does not exist for check {criterion.id}")
                    continue

                # 2. Check the File Hash
                # -L follows symlinks for the hash calculation
                hash_cmd = f"sha256sum {filepath} | cut -d' ' -f1"
                stdin, stdout, stderr = client.exec_command(hash_cmd)
                
                actual_hash = stdout.read().decode().strip()
                client.close()

                if actual_hash == expected_hash:
                    return (criterion.team, f"Found expected content for check {criterion.id}")
                else:
                    err.append(f"File {filepath} does not match expected hash for check {criterion.id}")

            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])

class Workstation_windows (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter_by(host_id == self.host)

        for user in users:
            if user in ALL_LOCAL:
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                username = user[0]
                password = user[1]
                filepath = criterion.location
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
                ps_script = f"""
                $path = "{filepath}"
                if (Test-Path $path) {{
                    $item = Get-Item -Path $path
                    $perm = (Get-Acl $item.FullName).Access | Where-Object {{ 
                        $_.IdentityReference -eq "{username}" -or $_.IdentityReference -eq "Everyone" 
                    }} | Where-Object {{ $_.FileSystemRights -match "ExecuteFile|FullControl" }}
                    
                    $hash = (Get-FileHash $item.FullName -Algorithm SHA256).Hash
                    
                    if ($perm -and ($hash -eq "{expected_hash}")) {{
                        Write-Output "Found expected content"
                    }} else {{
                        Write-Output "File {filepath} does not match expected hash or is not executable"
                    }}
                }} else {{
                    Write-Output "File {filepath} does not exist"
                }}
                """

                shell_id = p.open_shell()
                command_id = p.run_command(shell_id, 'powershell', ['-Command', ps_script])
                std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
                p.cleanup_command(shell_id, command_id)
                p.close_shell(shell_id)

                output = std_out.decode().strip()
                firstword = output.split(" ")[0].strip()
                if ((firstword != "File") and (firstword != "Found")):
                    raise ValueError(output)
                
                if firstword == "Found":
                    return (criterion.team, f"{output} for check {criterion.id}")
                else:
                    err.append(f"{output} for check {criterion.id}")

            except Exception as E:
                err.append(f"{E[:MAX_ERROR_LEN]}")
        
        return (0, err[0])