import threading
import time
import sdnotify
# Import your functions from your main app file
from server import (
    app, db, 
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
def check(check_func:Callable, args:list, service_id:int, out:dict[int, int]):
    out[check_name] = -1
    out[check_name] = check_func(args)

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
        return

    # Perform checks
    round_num:int = 1
    while True:
        logger.info(f'Beginning to score round {round_num}')

        res : dict[int, int] = {} # Relate service ID to result
        # Get check info
        for service in services:
            # Load in scoring criteria
            session.query(ScoringCriteria).\
                filter(ScoringCriteria.service_id == service.id)
            # Match to score type (HTTP, etc)
            # Add new thread to checks dict, with value being -1

        # Start checks
        for check in checks:
            check.start()

        # Wait for checks
        time.sleep(60)

        # Update to service history
        for service in services:
            newScore = ScoringHistory(
                service_id = service.id,
                host_id = service.host_id,
                round = round_num,
                value = res[services.id]
            )
            db.session.add(new_score)
            logger.info(f"Created round {round_num} for service {service_id}")
            db.session.commit()

        # Increment round number
        round_num ++

            

    # Keep the main process alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")