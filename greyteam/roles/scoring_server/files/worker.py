import threading
import multiprocessing as mp
import time
import sdnotify
import json
import urllib
import math
from shared import (
CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE, CREATE_TEST_DATA,
DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, SECRET_KEY, NETCAT_PORT,
setup_logging)
from models import (
db, AuthToken, WebUser, WebhookQueue, Host,
ScoringUser, ScoringUserList, Service, ScoringHistory, ScoringCriteria, ScoringTeams
)
import socket
import threading
import time
from tabulate import tabulate
from server import app, get_scoring_data_latest
from data import create_db_tables
import copy

logger = setup_logging("server_worker")
MAX_MESSAGE_DISCORD = 130

# === WEBHOOK ===

def webhook_main():
    """Dedicated rate-limited sender thread with dynamic rate limiting."""
    if not WEBHOOK_URL:
        logger.error(f"/webhook_main - no WEBHOOK URL provided, exiting! {WEBHOOK_URL}")
        return

    last_60_seconds = []

    logger.info("/webhook_main - starting main loop")
    
    while True:
        try:
            sleep_time = 0
            with app.app_context():
                # Find the oldest unprocessed task
                task = WebhookQueue.query.order_by(WebhookQueue.created_at.asc()).first()
                
                if not task:
                    logger.info("/webhook_main - no webhooks in queue, sleeping.")
                    time.sleep(2) # Wait a bit before checking for new tasks again
                    continue

                # Send the webhook
                resp, body = discord_webhook(task)

                try:
                    if resp.code == 429:
                        # Rate limited by Discord
                        bodyDict = json.loads(body)
                        sleep_time = float(bodyDict["retry_after"])

                        logger.warning(f"/webhook_main - message {task.id}: Retry_After detected, re-queued message {task.id} and sleeping for {sleep_time}.")
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
                                    logger.info(f"/webhook_main - message {task.id}: 0 responses remaining, sleeping for {sleep_time}.")
                            except ValueError:
                                sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                                logger.warning(f"/webhook_main - message {task.id}: failed to parse headers, sleeping {sleep_time}.")
                        else:
                            sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                            logger.warning(f"/webhook_main - message {task.id}: Missing rate limit headers, sleeping {sleep_time}.")

                except Exception as e:
                    db.session.rollback()
                    sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                    db.session.delete(task)
                    db.session.commit()
                    logger.error(f"/webhook_main - caught unknown error from discord_webhook, deleting message {task.id} from webhook queue - {e}.")

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
        except Exception as E:
            logger.info(f"/webhook_main - generic error: {E}")

def discord_webhook(task,url=WEBHOOK_URL):
    #compare rules level to set colors of the alert
    if not url:
        return
    
    color = "5e5e5e" # unknown
    
    try:
        if ("web user" in task.title.lower().strip()):
            color = "641f1a"
        elif ("scoring user" in task.title.lower().strip()):
            color = "91251e"
        elif (task.title.lower().split(' ')[0]  == "token"):
            color = "8C573A"
        elif (task.title.lower().split(' ')[0]  == "host"):
            color = "a37526"
        elif ("scoring criteria" in task.title.lower().strip()):
            color = "404C24"
        elif (task.title.lower().split(' ')[0] == "scoring"):
            color = "6d39cf"
        elif (task.title.lower().split(' ')[0] == "ir"):
            color = "4e08aa"
        elif (task.title.lower().split(' ')[0] == "inject"):
            color = "036995"
        elif (task.title.lower().split(' ')[0] == "uptime"):
            color = "380a8e"
        elif (task.title.lower().split(' ')[0]  == "file"):
            color = "b11226"

    except Exception as E:
        # weird format, fallback to generic color
        pass

    #data that the webhook will receive and use to display the alert in discord chat
    payload = json.dumps({
    "embeds": [
        {
        "title": f"{task.title}"[:250] if task.title.strip() else "No Title",
        "color": int(color,16),
        "description": f"{task.content}"[:4000] if task.content.strip() else "No Content"#,
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
    #logger.info(f"{data}")
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

# === Netcat ===

class ScoreboardManager:
    def __init__(self):
        self.clients = []
        self.last_round = -1
        self.lock = threading.Lock()

    def add_client(self, client_socket):
        with self.lock:
            self.clients.append(client_socket)
        # Immediately send the current data so they aren't staring at a blank screen
        self.push_to_single(client_socket)

    def push_to_single(self, client_socket):
        """Sends current state to a newly connected client."""
        with app.app_context():
            data, current_round = get_scoring_data_latest()
            if data:
                payload = self.format_payload(data, current_round)
                try:
                    client_socket.sendall(payload.encode('utf-8'))
                except Exception as E:
                    logger.error(f"/push_to_single - error when sending data to client - {E}.")
            else:
                logger.error(f"/push_to_single - error when sending data to client - did not return any data.")

    def format_payload(self, input_data, round_num):
        """Standardized formatting for CLI clients."""
        data = copy.deepcopy(input_data)
        # Add ANSI Colors
        for row in data:
            team = row['team'].lower()
            if "blue" in team:
                #row['team'] = f"\033[92m{row['team']}\033[0m" # Green
                row['team'] = f"\033[94m{row['team']}\033[0m" # Blue
            elif "red" in team:
                row['team'] = f"\033[91m{row['team']}\033[0m" # Red
            elif "offline" in team:
                row['team'] = f"\033[93m{row['team']}\033[0m" # yellow

        clear_screen = "\033[H\033[2J"
        header = f"\033[1m=== LIVE SCOREBOARD - ROUND {round_num} ===\033[0m\n"
        table = tabulate(data, headers="keys", tablefmt="grid")
        footer = f"\nUpdated: {time.strftime('%H:%M:%S')} | Active Clients: {len(self.clients)}\n"
        return clear_screen + header + table + footer

    def broadcast_loop(self):
        logger.info("Central Manager loop started.")
        while True:
            with app.app_context():
                data, current_round = get_scoring_data_latest()

                if current_round and current_round > self.last_round:
                    logger.info(f"New round {current_round} detected! Broadcasting to {len(self.clients)} clients...")
                    
                    try:
                        data_discord = copy.deepcopy(data)
                        for row in data_discord:
                            team = row['team'].lower()
                            if "blue" in team:
                                row['team'] = f"🟦{row['team']}" # Blue # Green🟩
                            elif "red" in team:
                                row['team'] = f"🟥{row['team']}" # Red
                            elif "offline" in team:
                                row['team'] = f"🟨{row['team']}" # yellow
                            row['message'] = row['message'][:MAX_MESSAGE_DISCORD] + "..." if len(row['message']) > MAX_MESSAGE_DISCORD else row['message']
                        table = tabulate(data_discord, headers="keys", tablefmt="simple")#tablefmt="grid")
                        task = WebhookQueue(
                            title=f"Scoring Round {current_round}",
                            content=f"```\n{table}\n```"
                        )
                        db.session.add(task)
                        db.session.commit()
                    except Exception as E:
                        db.session.rollback()
                        logger.error(f"Error when adding scoring round to webhook queue: {E}")

                    # Push to all NC Clients
                    payload = self.format_payload(data, current_round).encode('utf-8')
                    
                    with self.lock:
                        disconnected = []
                        for client in self.clients:
                            try:
                                client.sendall(payload)
                            except:
                                disconnected.append(client)
                        
                        # Clean up dead connections
                        for dead in disconnected:
                            self.clients.remove(dead)
                    
                    self.last_round = current_round
            
            time.sleep(20)

def handle_client(manager, client_socket, addr):
    manager.add_client(client_socket)
    # We don't need a loop here anymore; the manager pushes updates.
    # We just keep the thread alive to detect when the client closes the connection.
    try:
        logger.info(f"/handle_client - new netcat client connected from {addr}")
        while True:
            # If recv returns empty, client disconnected
            if not client_socket.recv(1024): break
    except:
        pass
    finally:
        with manager.lock:
            if client_socket in manager.clients:
                manager.clients.remove(client_socket)
        logger.info(f"/handle_client - client {addr} disconnected")
        client_socket.close()

def start_nc_server(manager, port=9000):

    logger.info(f"/start_nc_server - starting netcat server on port {port}")

    # Start the broadcaster in its own thread
    threading.Thread(target=manager.broadcast_loop, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(50)

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(manager, client, addr), daemon=True).start()

if __name__ == "__main__":
    logger.info("Starting server worker threads...")
    notifier = sdnotify.SystemdNotifier()
    with app.app_context():
        create_db_tables(logger)
    manager = ScoreboardManager()
    
    threads = [
        threading.Thread(target=webhook_main, daemon=True),
        threading.Thread(target=start_nc_server, args=(manager,NETCAT_PORT,), daemon=True),
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
        logger.warning("Worker exiting")