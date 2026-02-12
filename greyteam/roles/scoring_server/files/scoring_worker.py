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
from sqlalchemy import func

import checks
import multiprocessing as mp
import sys

logger = setup_logging("scoring_worker")

def check(service:Service) -> tuple[int, str]:
    """
    Used by processes to output check results to the main thread

    Parameters
    ---
    service : Service
        The Service object to perform a check for
    """
    # Match scorecheck name to a check
    check_obj : checks.Check = None

    match service.scorecheck_name:
        case 'http':
            check_obj = checks.Http(service)
        case _: # Default: no class match
            return (0, f'Check type "{service.scorecheck_name}" not implemented.')

    return check_obj.check()

def get_services() -> list[Service]:
    """
    Pull all services from the database
    
    :return: list of Services in the database
    :rtype: list[Service]
    """
    # Pull services from db
    try:
        logger.info("Pulling services")
        services:list[Service] = Service.query.all()
    except Exception as e:
        logger.error("Failed to pull services - Exiting...")
        sys.exit()
    
    return services

def run_scoring_round(round_num:int, services:list[Service]):
    '''
    Run a scoring round.

    Creates a process per check, waits 60 seconds, then harvests
    the results from the check. Then creates a history entry per
    check.
    
    :param round_num: The current round number
    :type round_num: int
    :param services: The services being scored
    :type services: list[Service]
    '''

    logger.info(f"Worker checking {len(services)} services")
    # Pool of processes
    with mp.Pool(processes=len(services)) as pool:
        # Carry out checks
        processes = [pool.apply_async(check, (service,)) for service in services]

        # Wait for round end
        time.sleep(60)

        # Load into service history
        for i in range(len(services)):
            try:
                # I use timeout of 0 b/c I already waited above
                # Use of async is mostly to get the timeout error
                res = processes[i].get(0)
            except mp.TimeoutError as e:
                res = (0, "Check timed out")
            except Exception as e:
                res = (0, "Something went wrong with scoring multiprocessing")

            # Construct score
            new_score = ScoringHistory (
                service_id = services[i].id,
                host_id = services[i].host_id,
                round = round_num,
                value = res[0],
                message = res[1]
            )
            db.session.add(new_score)
        
    db.session.commit()

if __name__ == "__main__":
    logger.info("Scoring worker started")
    with app.app_context():
        logger = setup_logging("scoring_worker")
        logger.info("Starting scoring worker threads...")

        # Get starting round number from database
        total_services_count = db.session.query(func.count(Service.id)).scalar()
        highest_complete_round = db.session.query(ScoringHistory.round) \
            .group_by(ScoringHistory.round) \
            .having(func.count(ScoringHistory.service_id.distinct()) == total_services_count) \
            .order_by(ScoringHistory.round.desc()) \
            .first()
        round_num = (highest_complete_round[0] if highest_complete_round else 0) + 1

        while True:
            # Pull services from db
            services = get_services()
            # Run round
            logger.info(f"Starting scorechecks for Round {round_num}")
            run_scoring_round(round_num, services)
            round_num += 1