import subprocess
import random
from server import (
    Service, ScoringUser, ScoringCriteria, Host
)

MAX_ERROR_LEN = 200

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
            res = subprocess.run(
                ["mysql", "-h", self.host_ip,
                "-u", f"{user[0]}"
                "-p", f"{user[1]}",
                "Ponies", "-e", "\"SELECT ponies\""],
                capture_output=True,
                text=True
            ) # Expected: 30
            
            # Check succeeded
            if res.returncode == 0 and criterion.content in res.stdout:
                return (criterion.team, f"Found expected content for check {criterion.id}")
            # Command failed
            elif res.returncode != 0:
                err.insert(0, res.stderr)
            # Incorrect output
            elif criterion.content not in res.stdout:
                err.append(f"Could not find expected content for check {criterion.id}")
        
        return (0, err[0])

class Ssh (Check):
    users:list[tuple[str,str]]

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter_by(host_id == self.host)

        for user in users:
            self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)
        sshProcess = subprocess.Popen(
            ['ssh', f'{user[0]}@{self.host_ip}'],
            input=user[1]
        )

class Mssql (Check):
    users:list[tuple[str,str]]  

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        users:list[ScoringUser] = ScoringUser.query.filter_by(host_id == self.host)

        for user in users:
            if user in ["celestia","discord","luna","starswirl"]: # only domain admins
                self.users.append((user.username, user.password))

    def check (self):
        user = random.choice(self.users)

        err = []
        for criterion in self.criteria:
            try:
                username = user[0]
                password = user[1]
                domain = "MLP.LOCAL"
                target_host = f"{criterion.content.split(":")[0]},{criterion.content.split(":")[1]}"
                db_name = "db"

                # Pipe the password to kinit using the input parameter
                kinit_proc = subprocess.run(
                    ['kinit', f"{username}@{domain}"],
                    input=password.encode(),
                    capture_output=True,
                    check=True
                )

                # Execute sqlcmd using the Kerberos ticket (-E)
                # -s"," sets comma as separator, -W removes trailing spaces, -h-1 removes headers
                res = subprocess.run(
                    [
                        'sqlcmd', '-E', '-C', 
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