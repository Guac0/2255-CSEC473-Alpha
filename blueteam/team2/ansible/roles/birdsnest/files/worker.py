import threading
import time
from datetime import datetime
import math
import urllib.request
import urllib.error
import json
import subprocess
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from shared import (
setup_logging, User, CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, STALE_TIME, DEFAULT_WEBHOOK_SLEEP_TIME,
MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL, INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL, CREATE_TEST_DATA, SECRET_KEY,
GIT_PROJECT_ROOT, GIT_BACKEND, DATABASE_CREDS, DATABASE_LOCATION, DATABASE_DB
)
from models import (
db,
Agent, Message, Incident, AuthToken, AuthTokenAgent, WebUser, AnsibleResult, AnsibleVars,
AuthConfig, AuthConfigGlobal, AuthRecord, WebhookQueue, AnsibleQueue, AgentTask, SystemUser
)
from utilities import (
insert_initial_data, create_db_tables, serialize_model, is_safe_path,
get_random_time_offset_epoch, add_test_data_agents, add_test_data_messages, add_test_data_incidents,
add_test_data_incidents_custom, add_test_data_auth_records, add_test_data_auth_config,
run_git, hash_id, create_incident, clean_and_join_path, get_git_stats, find_incident, find_incident_db
)
SQLALCHEMY_DATABASE_URI = f"postgresql+psycopg2://{ DATABASE_CREDS }@{ DATABASE_LOCATION }/{ DATABASE_DB }"
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['SECRET_KEY'] = CONFIG["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db.init_app(app)
def webhook_main():
    if not WEBHOOK_URL:
        return
    last_60_seconds = []
    while True:
        sleep_time = 0
        with app.app_context():
            task = WebhookQueue.query.order_by(WebhookQueue.created_at.asc()).first()
            if not task:
                time.sleep(2) 
                continue
            incident = Incident.query.get(task.incident_id)
            if not incident:
                db.session.delete(task)
                db.session.commit()
                continue
            incident_payload = {
                "timestamp": incident.timestamp,
                "agent_id": incident.agent_id,
                "oldStatus": incident.oldStatus,
                "tag": incident.tag,
                "newStatus": incident.newStatus,
                "message": incident.message,
                "assignee": incident.assignee,
                "sla": incident.sla
            }
            resp, body = discord_webhook(task.incident_id, incident_payload)
            try:
                if resp.code == 429:
                    bodyDict = json.loads(body)
                    sleep_time = float(bodyDict["retry_after"])
                    logger.warning(f"/webhook_main - Retry_After succeeded, re-queued incident and sleeping for {sleep_time}.")
                else:
                    db.session.delete(task)
                    db.session.commit()
                    remaining = resp.getheader("X-RateLimit-Remaining")
                    reset_after = resp.getheader("X-RateLimit-Reset-After")
                    if remaining is not None and reset_after is not None:
                        try:
                            remaining_int = int(remaining)
                            reset_after_float = float(reset_after)
                            if remaining_int == 0:
                                sleep_time = reset_after_float
                                logger.info(f"/webhook_main - incident {incident.incident_id}: 0 responses remaining, sleeping for {sleep_time}.")
                        except ValueError:
                            sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                            logger.warning(f"/webhook_main - incident {incident.incident_id}: failed to parse headers, sleeping {sleep_time}.")
                    else:
                        sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                        logger.warning(f"/webhook_main - Missing rate limit headers, sleeping {sleep_time}.")
            except Exception as e:
                sleep_time = DEFAULT_WEBHOOK_SLEEP_TIME
                db.session.delete(task)
                db.session.commit()
                logger.error(f"/webhook_main - caught unknown error from discord_webhook, deleting incident {task.incident_id} from webhook queue - {e}.")
        last_60_seconds.append(time.time())
        for incTime in last_60_seconds:
            if (time.time() - incTime) > 60:
                last_60_seconds.remove(incTime)
        if len(last_60_seconds) >= MAX_WEBHOOK_MSG_PER_MINUTE - 1:
            new_sleep_time = 60 - (time.time() - last_60_seconds[0]) 
            if new_sleep_time < sleep_time: 
                new_sleep_time = sleep_time
            new_sleep_time = math.ceil(new_sleep_time * 100) / 100 
            if new_sleep_time > (60 / MAX_WEBHOOK_MSG_PER_MINUTE): 
                logger.info(f"/webhook_main - client side ratelimiting enabled: sleeping for {new_sleep_time} seconds. Old sleep_time: {sleep_time}. len(last_60_seconds): {len(last_60_seconds)}. MAX_WEBHOOK_MSG_PER_MINUTE: {MAX_WEBHOOK_MSG_PER_MINUTE}.") 
            sleep_time = new_sleep_time 
        time.sleep(sleep_time)
def discord_webhook(incident_id,incident,url=WEBHOOK_URL):
    if not url:
        return
    color = "5e5e5e" 
    try:
        if (incident["message"].lower().split(' ')[0]  == "firewall"):
            color = "641f1a"
        elif (incident["message"].lower().split(' ')[0]  == "interface"):
            color = "91251e"
        elif (incident["message"].lower().split(' ')[0]  == "service"):
            color = "8C573A"
        elif (incident["message"].lower().split(' ')[0]  == "servicecustom"):
            color = "a37526"
        elif (incident["message"].lower().split(' ')[0] == "agent"):
            color = "404C24"
        elif (incident["message"].lower().split(' ')[0] == "server"):
            color = "6d39cf"
        elif (incident["message"].lower().split(' ')[0] == "ir"):
            color = "4e08aa"
        elif (incident["message"].lower().split(' ')[0] == "inject"):
            color = "036995"
        elif (incident["message"].lower().split(' ')[0] == "uptime"):
            color = "380a8e"
        elif (incident["message"].lower().split(' ')[0]  == "file"):
            color = "b11226"
    except Exception as E:
        pass
    try:
        incident_record = db.session.get(Incident,incident_id)
        agent = db.session.get(Agent,incident_record.agent_id)
        if not agent:
            raise KeyError
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - {} Incident Created on {} for {}".format(incident["message"].split('-')[0].strip(),agent.hostname,agent.agent_name),
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            "url": f"{PUBLIC_URL}/incidents?incident_id={incident_id}",
            "fields": [
                {
                "name": "Incident #",
                "value": "{}".format(incident_id),
                "inline": True
                },
                {
                "name": "Timestamp",
                "value": "{}".format(datetime.fromtimestamp(incident["timestamp"])),
                "inline": True
                },
                {
                "name": "Autofix Status",
                "value": "{}".format(incident["newStatus"]),
                "inline": True
                },
                {
                "name": "Agent Name",
                "value": "{}".format(agent.agent_name),
                "inline": True
                },
                {
                "name": "Hostname",
                "value": "{}".format(agent.hostname),
                "inline": True
                },
                {
                "name": "IP Address",
                "value": "{}".format(agent.ip),
                "inline": True
                }
            ]
            }
        ]
        })
    except KeyError as E:
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - Custom {} Incident Created".format(incident["message"].split('-')[0].strip()),
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            "url": f"{PUBLIC_URL}/incidents?incident_id={incident_id}",
            "fields": [
                {
                "name": "Incident #",
                "value": "{}".format(incident_id),
                "inline": True
                },
                {
                "name": "Timestamp",
                "value": "{}".format(datetime.fromtimestamp(incident["timestamp"])),
                "inline": True
                },
                {
                "name": "Autofix Status",
                "value": "{}".format(incident["newStatus"]),
                "inline": True
                }
            ]
            }
        ]
        })
    except IndexError as E:
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - Custom Generic Incident Created",
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            "url": f"{PUBLIC_URL}/incidents?incident_id={incident_id}",
            "fields": [
                {
                "name": "Incident #",
                "value": "{}".format(incident_id),
                "inline": True
                },
                {
                "name": "Timestamp",
                "value": "{}".format(datetime.fromtimestamp(incident["timestamp"])),
                "inline": True
                },
                {
                "name": "Autofix Status",
                "value": "{}".format(incident["newStatus"]),
                "inline": True
                }
            ]
            }
        ]
        })
    headers = {
        'content-type': 'application/json',
        'Accept-Charset': 'UTF-8',
        'User-Agent': 'python-urllib/3' 
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
            logger.info(f"/discord_webhook - sent message for incident {incident_id}.")
            body = resp.read().decode('utf-8') if resp.fp else ''  
            return resp, body  
    except urllib.error.HTTPError as err: 
        body = err.read().decode('utf-8') if err.fp else ''
        logger.error(f"/discord_webhook - failed to send message for incident {incident_id}. StatusCode: {err.code}. Body: {body}.") 
        return err,body
def periodic_stale(interval=60):
    logger.info("periodic_stale() started.")
    while True:
        time.sleep(interval)
        with app.app_context():
            try:
                agents_records = Agent.query.filter(Agent.agent_id != 'custom').all()
                agents_updated = False
                for agent in agents_records:
                    if agent.agent_name == "custom":
                        continue
                    time_since_seen = time.time() - agent.lastSeenTime
                    if agent.stale and time_since_seen < STALE_TIME:
                        agent.stale = False
                        agents_updated = True
                        criteria = {
                            "agent_id": agent.agent_id,
                            "tag": ('New', 'Active'),
                            "message": f"Agent - Agent {agent.agent_name} on {agent.hostname} moved to Stale state. Last seen {datetime.fromtimestamp(agent.lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}."
                        }
                        incident_id = find_incident_db(criteria, newest=True)
                        if incident_id:
                            incident = db.session.get(Incident, incident_id)
                            if incident:
                                incident.tag = "Closed"
                                logger.info(f"periodic_stale(): Stale incident {incident_id} CLOSED for {agent.agent_id}.")
                        logger.info(f"periodic_stale(): Agent {agent.agent_id} recovered.")
                    elif not agent.stale and time_since_seen > STALE_TIME:
                        agent.stale = True
                        agents_updated = True
                        incident_data = {
                            "timestamp": time.time(),
                            "agent_id": agent.agent_id,
                            "oldStatus": agent.lastStatus,
                            "newStatus": False,
                            "message": f"Agent - Agent {agent.agent_name} on {agent.hostname} moved to Stale state. Last seen {datetime.fromtimestamp(agent.lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}.",
                            "sla": 0
                        }
                        create_incident(incident_data)
                        logger.info(f"periodic_stale(): Agent {agent.agent_id} moved to stale state.")
                if agents_updated:
                    db.session.commit()
                    logger.info("periodic_stale(): Database updated.")
                else:
                    logger.info("periodic_stale(): No changes.")
            except Exception as e:
                db.session.rollback()
                logger.error(f"periodic_stale(): Loop encountered error: {e}")
def periodic_ansible(interval=5):
    logger.info("periodic_ansible(): started.")
    while True:
        with app.app_context():
            item = AnsibleQueue.query.order_by(AnsibleQueue.created_at.asc()).first()
            if not item:
                time.sleep(interval)
                continue
            if item.ansible_venv:
                command = f"source {item.ansible_venv} && cd {item.ansible_folder} && ansible-playbook {item.ansible_playbook} -i {item.ansible_inventory} -l {item.dest_ip} -t magpie_client_auto {item.extra_vars}"
            else:
                command = f"cd {item.ansible_folder} && ansible-playbook {item.ansible_playbook} -i {item.ansible_inventory} -l {item.dest_ip} -t magpie_client_auto {item.extra_vars}"
            logger.info(f"periodic_ansible(): starting subprocess for task {item.id}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True, 
                text=True, 
                check=False
            )
            newResult = AnsibleResult(
                task=item.id,
                returncode=result.returncode,
                result=f"STDOUT: {result.stdout.strip()} ||| STDERR: {result.stderr.strip()}"
            )
            db.session.add(newResult)
            db.session.delete(item)
            db.session.commit()
            logger.info(f"periodic_ansible(): finished task {newResult.task}. Returncode: {result.returncode}")
        time.sleep(1)
def periodic_cleanup():
    logger.info("periodic_cleanup() started.")
    while True:
        try:
            with app.app_context():
                session_interface = app.session_interface
                if hasattr(session_interface, 'sql_session_model'):
                    model = session_interface.sql_session_model
                    expired = model.query.filter(model.expiry < datetime.utcnow()).delete()
                    db.session.commit()
                    if expired:
                        logger.info(f"Background Task: Deleted {expired} expired sessions.")
        except Exception as e:
            logger.error(f"Cleanup Error: {e}")
        time.sleep(900)
if __name__ == "__main__":
    logger = setup_logging("worker",app)
    logger.info("Starting background worker threads...")
    create_db_tables(app)
    threads = [
        threading.Thread(target=webhook_main, daemon=True),
        threading.Thread(target=periodic_stale, daemon=True),
        threading.Thread(target=periodic_cleanup, daemon=True),
        threading.Thread(target=periodic_ansible, daemon=True)
    ]
    for t in threads:
        t.start()
    with open("/tmp/worker_ready", "w") as f:
        f.write("ready")
    logger.info("Started background worker threads.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")