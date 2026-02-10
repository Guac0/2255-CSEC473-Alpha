import threading
import time
import sdnotify
import json
import urllib
import math
from shared import (
CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE,
DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, SECRET_KEY, 
setup_logging)
from models import (
db, AuthToken, WebUser, WebhookQueue, Host,
ScoringUser, ScoringUserList, Service, ScoringHistory, ScoringCriteria
)
from server import app

# === WEBHOOK ===

def webhook_main():
    """Dedicated rate-limited sender thread with dynamic rate limiting."""
    if not WEBHOOK_URL:
        return

    last_60_seconds = []
    
    while True:
        sleep_time = 0
        with app.app_context():
            # Find the oldest unprocessed task
            task = WebhookQueue.query.order_by(WebhookQueue.created_at.asc()).first()
            
            if not task:
                time.sleep(2) # Wait a bit before checking for new tasks again
                continue

            # Send the webhook
            resp, body = discord_webhook(task)

            try:
                if resp.code == 429:
                    # Rate limited by Discord
                    bodyDict = json.loads(body)
                    sleep_time = float(bodyDict["retry_after"])

                    logger.warning(f"/webhook_main - Retry_After succeeded, re-queued incident and sleeping for {sleep_time}.")
                else:
                    db.session.delete(task)
                    db.session.commit()

                    # Maybe rate-limit headers present
                    remaining = resp.getheader("X-RateLimit-Remaining")
                    reset_after = resp.getheader("X-RateLimit-Reset-After")

                    if remaining is not None and reset_after is not None:
                        try:
                            remaining_int = int(remaining)
                            reset_after_float = float(reset_after)

                            if remaining_int == 0:
                                sleep_time = reset_after_float
                                logger.info(f"/webhook_main - incident {task.id}: 0 responses remaining, sleeping for {sleep_time}.")
                        except ValueError:
                            sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                            logger.warning(f"/webhook_main - incident {task.id}: failed to parse headers, sleeping {sleep_time}.")
                    else:
                        sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                        logger.warning(f"/webhook_main - Missing rate limit headers, sleeping {sleep_time}.")

            except Exception as e:
                db.session.rollback()
                sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                db.session.delete(task)
                db.session.commit()
                logger.error(f"/webhook_main - caught unknown error from discord_webhook, deleting incident {task.id} from webhook queue - {e}.")

        last_60_seconds.append(time.time())

        for incTime in last_60_seconds:
            if (time.time() - incTime) > 60:
                last_60_seconds.remove(incTime)
        
        if len(last_60_seconds) >= MAX_WEBHOOK_MSG_PER_MINUTE - 1:
            new_sleep_time = 60 - (time.time() - last_60_seconds[0]) # how long until first message is out of the 60 second window
            if new_sleep_time < sleep_time: # dont go below existing ratelimit if any
                new_sleep_time = sleep_time
            new_sleep_time = math.ceil(new_sleep_time * 100) / 100 # round to 2 decimals
            if new_sleep_time > (60 / MAX_WEBHOOK_MSG_PER_MINUTE): # reduce noise in normal operation
                logger.info(f"/webhook_main - client side ratelimiting enabled: sleeping for {new_sleep_time} seconds. Old sleep_time: {sleep_time}. len(last_60_seconds): {len(last_60_seconds)}. MAX_WEBHOOK_MSG_PER_MINUTE: {MAX_WEBHOOK_MSG_PER_MINUTE}.") 
            sleep_time = new_sleep_time # If we are client side ratelimited, set extra time to compensate for discord channel ratelimiting (wait until oldest message drops off)

        # Rate limit enforcement
        #time.sleep(max(sleep_time,0.2))
        time.sleep(sleep_time)

def discord_webhook(task,url=WEBHOOK_URL):
    #compare rules level to set colors of the alert
    if not url:
        return
    
    color = "5e5e5e" # unknown
    
    try:
        if ("web user" in task.Title.lower().strip()):
            color = "641f1a"
        elif ("scoring user" in task.Title.lower().strip()):
            color = "91251e"
        elif (task.Title.lower().split(' ')[0]  == "token"):
            color = "8C573A"
        elif (task.Title.lower().split(' ')[0]  == "host"):
            color = "a37526"
        elif ("scoring criteria" in task.Title.lower().strip()):
            color = "404C24"
        elif (task.Title.lower().split(' ')[0] == "scoring"):
            color = "6d39cf"
        elif (task.Title.lower().split(' ')[0] == "ir"):
            color = "4e08aa"
        elif (task.Title.lower().split(' ')[0] == "inject"):
            color = "036995"
        elif (task.Title.lower().split(' ')[0] == "uptime"):
            color = "380a8e"
        elif (task.Title.lower().split(' ')[0]  == "file"):
            color = "b11226"

    except Exception as E:
        # weird format, fallback to generic color
        pass

    #data that the webhook will receive and use to display the alert in discord chat
    payload = json.dumps({
    "embeds": [
        {
        "title": f"{task.Title}",
        "color": int(color,16),
        "description": f"{task.Content}"#,
        #"url": f"{PUBLIC_URL}/incidents?incident_id={incident_id}",
        #"fields": [
        #    {
        #    "name": "Incident #",
        #    "value": "{}".format(incident_id),
        #    "inline": True
        #    }
        #]
        }
    ]
    })

    headers = {
        'content-type': 'application/json',
        'Accept-Charset': 'UTF-8',
        'User-Agent': 'python-urllib/3' # Required for urllib, automatic with requests
    }
    data = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info(f"/discord_webhook - sent message for WebhookQueue task id {task.id}.")

            #status_code = resp.getcode()
            #status_text = resp.read().decode("utf-8")
            #response_headers = resp.getheaders()   # <-- tuple list of headers

            #print("Status Code:", status_code)
            #print("Headers:")
            #for k, v in response_headers:
            #    print(f"  {k}: {v}")
            #print("Body:")
            #print(status_text)

            body = resp.read().decode('utf-8') if resp.fp else ''  # consume body
            return resp, body  # return the response for headers inspection
    except urllib.error.HTTPError as err: #error is actually the full comm object
        body = err.read().decode('utf-8') if err.fp else ''
        logger.error(f"/discord_webhook - failed to send message for WebhookQueue task id {task.id}. StatusCode: {err.code}. Body: {body}.") # Headers: {err.headers}. 
        return err,body

if __name__ == "__main__":
    logger = setup_logging("server_worker")
    logger.info("Starting server worker threads...")
    notifier = sdnotify.SystemdNotifier()

    # Start the same threads you had before
    threads = [
        threading.Thread(target=webhook_main, daemon=True),
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