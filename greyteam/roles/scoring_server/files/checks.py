import subprocess
import random
from server import (
    Service, ScoringUser
)

''' The Check class. Acts as a template for all checks. '''
class Check:
    check_id:int
    host:str
    criteria:list[str]

    def __init__(self, check:Service) -> None:
        self.check_id = check.id
        self.host = check.host_id
        self.criteria = [criteria.content for criteria in check.scoringcriterias]

    '''
    Performs a check.

    @returns True if check succeeded, False if check failed
    '''
    def check () -> bool:
        return False

''' HTTP check, which checks if a piece of text is within a web response'''
class Http (Check):
    website:str
    text:str

    def __init__(self, check: Service) -> None:
        super().__init__(check)

        self.website = self.host

        # Attempt to match criteria with fields
        # This entire statement is BS'd
        for criterion in self.criteria:
            if "path" in criterion:
                self.website += criterion
            elif "text" in criterion:
                self.text = criterion
        

    def check (self):
        res = subprocess.run(
            ["curl", self.website],
            capture_output=True,
            text=True
        )

        if res.returncode != 0: return False

        if self.text in res.stdout: return True

        return False

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
            ['ssh', f'{user[0]}@{self.host}'],
            input=user[1]
        )