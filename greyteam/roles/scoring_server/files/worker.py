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

    # Keep the main process alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")