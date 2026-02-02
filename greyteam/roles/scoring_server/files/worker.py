import threading
import multiprocessing
import time
import sdnotify
import sys
import checks
# Import your functions from your main app file
from server import (
    app, db,
    ScoringCriteria, ScoringHistory, Service,
    CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE, SAVE_INTERVAL, STALE_TIME,
    DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
    INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
    AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL,
    CREATE_TEST_DATA,
    webhook_main, periodic_stale, create_incident,
    periodic_ansible, setup_logging, create_db_tables, start_server
)

'''
Used by threads to output check results to the main thread

@param check_func the function which carries out the check
@param args arguments to put into the check
@param service_id the ID of the service associated with the check
@param out the dictionary which takes the thread output. The key is service ID and the value is the check output (successful/nonsuccessful)
'''
def check(args: tuple[Service, dict[int, int]]):
    check_id:int = args[0].id
    res: dict[int,int] = args[1]

    # Match scorecheck name to a check
    check_obj:checks.Check = None
    match args[0].scorecheck_name:
        case 'http':
            check_obj = checks.Http(check_id)
        case _: # Default: no class match
            res[check_id] = 0
            return

    res[check_id] = 1 if check_obj.check(args) else 0

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
        services = Service.query.all()
    except Exception as e:
        logger.error("Failed to pull services - Exiting...")
        sys.exit()

    # Perform checks
    round_num:int = 1
    while True:
        logger.info(f'Beginning to score round {round_num}')

        res : dict[int, int] = {} # Relate service ID to result
        check_processes : list[multiprocessing.Process] = [] # Threads
        # Get check info
        for service in services:
            res[services.id] = -1

            check_processes.append(multiprocessing.Process(
                target= check,
                args= [service, res]
            ))
        # Start checks
        for check_process in check_processes:
            check_process.start()

        # Wait for checks
        time.sleep(60)

        # Stop all check processes
        # If a process hasn't finished, theres probably something funky
        # Going on
        for check_process in check_processes:
            if check_process.is_alive():
                check_process.terminate()

        # Update to service history
        for service in services:
            new_score = ScoringHistory(
                service_id = service.id,
                host_id = service.host_id,
                round = round_num,
                value = res[services.id]
            )
            db.session.add(new_score)
            logger.info(f"Created round {round_num} for service {service.id}")
            db.session.commit()

        # Increment round number
        round_num += 1

            

    # Keep the main process alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")