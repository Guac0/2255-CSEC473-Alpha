import subprocess
import random
from server import (
    Service, ScoringUser, ScoringCriteria
)


class Check:
    '''
    Template for all checks.

    Attributes
    ---
    check_id : int
        the ID of the service that we are conducting the check for
    host : str
        the IP of the host that we are conducting the check on
    criteria : list[str]
        a list of criteria for the check
    
    Methods
    ---
    check()
        performs a check, returning whether the check succeeded or failed
    '''
    check_id:int
    host:str
    criteria:list[str]

    def __init__(self, check:Service) -> None:
        self.check_id = check.id
        self.host = check.host_id
        self.criteria = [criteria.content for criteria in check.scoringcriterias]

    def update_criteria(self) -> None:
        '''
        Updates the criteria from the database
        '''
        criteria = ScoringCriteria.query.filter_by(service_id = self.check_id)
        
        self.criteria = [criterion.content for criterion in criteria]

    def check () -> bool:
        '''
        Performs a check.

        Returns
        ---
        bool
            True if check succeeds, False if check fails
        '''
        return False

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