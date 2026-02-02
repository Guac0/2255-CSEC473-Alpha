import threading
import multiprocessing as mp
import time
import sdnotify
import sys
import checks
# Import your functions from your main app file
from server import (
    app, db,
    ScoringHistory, Service, Host,
    CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE, SAVE_INTERVAL, STALE_TIME,
    DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
    INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
    AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL,
    CREATE_TEST_DATA,
    webhook_main, periodic_stale, create_incident,
    periodic_ansible, setup_logging, create_db_tables, start_server
)

def check(service:Service) -> bool:
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
            check_obj = checks.Http(service.id)
        case _: # Default: no class match
            return False

    return check_obj.check()

if __name__ == "__main__":
    logger = setup_logging()
    logger.info("Starting background worker threads...")
    notifier = sdnotify.SystemdNotifier()

    create_db_tables()

    # Start the same threads you had before
    threads = [
        #threading.Thread(target=periodic_autosave, daemon=True),
        threading.Thread(target=webhook_main, daemon=True),
        threading.Thread(target=periodic_stale, daemon=True),
        threading.Thread(target=periodic_ansible, daemon=True)#,
        # testing only!
        #threading.Thread(target=start_server, daemon=True)
        #gunicorn --certfile=cert.pem --keyfile=key.pem --workers 4 --bind 0.0.0.0:8080 server:app 
    ]

    for t in threads:
        t.start()
    
    notifier.notify("READY=1")
    logger.info("READY signal sent to systemd.")

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
                except mp.TimeoutError as e:
                    success = False
                except Exception as e:
                    success = False

                # Construct score
                new_score = ScoringHistory (
                    service_id = services[i].id,
                    host = services[i].host_id,
                    round = round_num,
                    value = success
                )
                db.session.add(new_score)
                logger.info(f"Created round {round_num} for service {services[i].id}")
                db.session.commit()
            
        round_num += 1

            

    # Keep the main process alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")