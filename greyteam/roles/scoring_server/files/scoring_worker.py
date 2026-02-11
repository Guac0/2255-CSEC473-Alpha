import time
from server import app
from shared import (
CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE,
DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, SECRET_KEY, 
setup_logging)
from models import (
db, AuthToken, WebUser, WebhookQueue, Host,
ScoringUser, ScoringUserList, Service, ScoringHistory, ScoringCriteria, ScoringTeams
)

import checks
import multiprocessing as mp
import sys

logger = setup_logging("scoring_worker")

def check(service:Service) -> int:
    """
    Used by processes to output check results to the main thread

    Parameters
    ---
    service : Service
        The Service object to perform a check for
    """
    # Match scorecheck name to a check
    check_obj : checks.Check = None
    try:
        match service.scorecheck_name:
            case 'http':
                check_obj = checks.Http(service.id)
            case _: # Default: no class match
                raise ValueError(f'Check type "{service.scorecheck_name}" not implemented.')
    except Exception as e:
        raise e

    return check_obj.check()

if __name__ == "__main__":
    logger = setup_logging("scoring_worker")
    logger.info("Starting scoring worker threads...")

    # Pull services from db
    try:
        logger.info("Pulling services")
        services:list[Service] = Service.query.all()
    except Exception as e:
        logger.error("Failed to pull services - Exiting...")
        sys.exit()

    # Perform checks
    round_num:int = 1
    while True:
        logger.info(f'Beginning to score round {round_num}')

        # Pool of processes
        with mp.Pool(processes=len(services)) as pool:
            # Carry out checks
            processes = [pool.apply_async(check, (service.id)) for service in services]

            # Wait for round end
            time.sleep(60)

            for i in range(services):
                try:
                    # I use timeout of 0 b/c I already waited above
                    # Use of async is mostly to get the timeout error
                    success = processes[i].get(0)
                    message = "Check succeeded"
                except mp.TimeoutError as e:
                    success = -1
                    message = "Check timed out"
                except Exception as e:
                    success = 0
                    message = e

                # Construct score
                new_score = ScoringHistory (
                    service_id = services[i].id,
                    host = services[i].host_id,
                    round = round_num,
                    value = success,
                    message = message
                )
                db.session.add(new_score)
                logger.info(f"Created round {round_num} for service {services[i].id}")
                db.session.commit()
            
        round_num += 1

def run_scoring_round():
    with app.app_context():
        # You now have full access to the DB using Flask syntax
        services = Service.query.all()
        logger.info(f"Worker checking {len(services)} services")
        
        for s in services:
            new_entry = ScoringHistory(service_id=s.id, value=1, message="Up")
            db.session.add(new_entry)
        
        db.session.commit()

if __name__ == "__main__":
    logger.info("Scoring worker started")
    while True:
        run_scoring_round()
        time.sleep(60)