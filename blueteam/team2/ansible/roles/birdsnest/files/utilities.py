from datetime import datetime
import re
import os
import base64
import subprocess
import platform
import time
import random
from sqlalchemy.orm import class_mapper
from werkzeug.security import generate_password_hash
from urllib.parse import urlparse, unquote_plus
import hashlib
from models import (
db,
Agent, Message, Incident, AuthToken, AuthTokenAgent, WebUser, AnsibleResult, AnsibleVars,
AuthConfig, AuthConfigGlobal, AuthRecord, WebhookQueue, AnsibleQueue, AgentTask, SystemUser
)
from shared import (
setup_logging, User, CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, STALE_TIME, DEFAULT_WEBHOOK_SLEEP_TIME,
MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL, INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL, CREATE_TEST_DATA, SECRET_KEY,
GIT_PROJECT_ROOT, GIT_BACKEND, DATABASE_CREDS, DATABASE_LOCATION, DATABASE_DB
)
logger = setup_logging()
def insert_initial_data():
    try:
        new_agent = Agent(
            agent_id="custom",
            agent_name="custom",
            agent_type="custom",
            hostname="N/A",
            ip="255.255.255.255",
            os="N/A",
            executionUser="N/A",
            executionAdmin=True,
            lastSeenTime=0,
            lastStatus=True,
            stale=True,
            pausedUntil=0
        )
        db.session.add(new_agent)
        if CREATE_TEST_DATA:
            add_test_data_agents(5)
            add_test_data_messages(10)
            add_test_data_incidents_custom(5)
            add_test_data_incidents(10)
            add_test_data_auth_records(20)
            add_test_data_auth_config()
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="strict_user")).scalar_one_or_none():
            config = AuthConfigGlobal(key="strict_user", value=AUTHCONFIG_STRICT_USER)
            db.session.add(config)
            logger.info(f"Initialized default strict_user={AUTHCONFIG_STRICT_USER}.")
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="strict_ip")).scalar_one_or_none():
            config = AuthConfigGlobal(key="strict_ip", value=AUTHCONFIG_STRICT_IP)
            db.session.add(config)
            logger.info(f"Initialized default strict_ip={AUTHCONFIG_STRICT_IP}.")
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="create_incident")).scalar_one_or_none():
            config = AuthConfigGlobal(key="create_incident", value=AUTHCONFIG_CREATE_INCIDENT)
            db.session.add(config)
            logger.info(f"Initialized default create_incident={AUTHCONFIG_CREATE_INCIDENT}.")
        if not db.session.execute(db.select(AuthConfigGlobal).filter_by(key="log_attempt_successful")).scalar_one_or_none():
            config = AuthConfigGlobal(key="log_attempt_successful", value=AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL)
            db.session.add(config)
            logger.info(f"Initialized default log_attempt_successful={AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL}.")
        existing_vars = db.session.get(AnsibleVars,"main")
        if not existing_vars:
            new_ansiblevars = AnsibleVars(id="main")
            db.session.add(new_ansiblevars)
            db.session.commit()
            logger.info(f"Initialized default AnsibleVars.")
        else:
            logger.info("AnsibleVars 'main' already exists, skipping initialization.")
        for token_value, data in INITIAL_AGENT_AUTH_TOKENS.items():
            new_token = AuthToken(
                token=token_value,
                timestamp=time.time(),
                added_by=data["added_by"]
            )
            db.session.add(new_token)
        for username, data in INITIAL_WEBGUI_USERS.items():
            hashed_password = generate_password_hash(data["password"])
            new_user = WebUser(
                username=username,
                password=hashed_password, 
                role=data["role"]
            )
            db.session.add(new_user)
        db.session.commit()
        logger.info("Successfully inserted initial Auth Tokens and Web Users.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"FATAL: Failed to insert initial data into DB: {e}")
def create_db_tables(app):
    with app.app_context():
        db.create_all()
        context = os.environ.get("APP_CONTEXT", "DEFAULT")
        if context == "WORKER":
            db_exists = WebUser.query.first()
            if not db_exists:
                insert_initial_data()
                logger.info(f"Initialized database with initial data inserted.")
            else:
                logger.info(f"Initialized database.")
def serialize_model(instance):
    mapper = class_mapper(instance.__class__)
    serialized_data = {}
    for column in mapper.columns:
        value = getattr(instance, column.key)
        serialized_data[column.key] = value
    return serialized_data
def get_random_time_offset_epoch(minutes_offset=30, direction="either"):
    current_epoch_time = time.time()
    seconds_offset = minutes_offset * 60
    if direction == "past":
        random_offset = -random.uniform(0, seconds_offset)
    elif direction == "future":
        random_offset = random.uniform(0, seconds_offset)
    elif direction == "either":
        random_offset = random.uniform(-seconds_offset, seconds_offset)
    else:
        raise ValueError("direction must be 'past', 'future', or 'either'")
    return current_epoch_time + random_offset
def add_test_data_agents(num=5):
    try:
        for i in range(1,num + 1):
            agent_name = ["apache2","iis","smb","mysql","vsftpd"][i-1]
            agent_type = random.choice(["magpie","owlet"])
            possible_hostnames = ["webserver1","webserver2","fileshare1","fileshare2","dc01"]
            hostname = possible_hostnames[i-1]
            possible_ips = ["10.1.1.1","10.1.1.2","10.1.1.3","10.1.1.4","10.1.1.5"]
            ip = possible_ips[i-1]
            possible_oses = ["Windows 10","Windows 2016Server","Ubuntu 16.03 Bookworm","RHEL 9.3","Rocky 8"]
            os_name = possible_oses[i-1]
            computed_agent_id = hash_id(agent_name, hostname, ip, os)
            new_agent = Agent(
                agent_id=computed_agent_id,
                agent_name=agent_name,
                agent_type=agent_type,
                hostname=hostname,
                ip=ip,
                os=os_name,
                executionUser=random.choice(["root", "admin", ".\\administrator", "domain\\dadmin", "user"]),
                executionAdmin=random.choice([True, False]),
                lastSeenTime=time.time() - ((num - i) * 100),
                lastStatus=random.choice([True, False]),
                stale=random.choice([True, False]),
                pausedUntil=random.choice([str(0),str(0),str(1),str(time.time()),str(time.time() + 180), str(time.time() + 600)])
            )
            db.session.add(new_agent)
            new_token = AuthTokenAgent(
                agent_id=computed_agent_id,
                added_by="test data",
                token=os.urandom(6).hex()
            )
            db.session.add(new_token)
        db.session.commit()
        logger.info(f"Successfully added {num} test agents to the database.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add test agent data: {e}")
def add_test_data_messages(num=15):
    try:
        all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
        for i in range(1, num + 1):
            timestamp = time.time() - ((num - i) * 100)
            agent_id = random.choice(all_agents).agent_id
            message_id = hash_id(timestamp, agent_id)
            new_message = Message(
                message_id = message_id,
                timestamp=timestamp,
                agent_id=agent_id,
                oldStatus=random.choice([False, True]),
                newStatus=random.choice([False, True]),
                message=random.choice([
                    "Service - Missing required package {package} for service {service}, DISARMED.",
                    "Service - Service {service_name} not running, RESTORED service to START state.",
                    "Service - Service {service_name} not set to automatic start, FAILED to set to automatic start.",
                    "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. SUCCESSFULLY created firewall rule Magpie_Rule_{port}_{direction}_{action}.",
                    "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. DISARMED, but told to create firewall rule Magpie_Rule_{port}_{direction}_{action}.",
                    "Firewall - SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.",
                    "Firewall - Could not get firewall rule information due to PowerShell error.",
                    "Interface - Interface {interface} was set to DOWN, RESTORED UP state.",
                    "Interface - Bad system TTL set, DISARMED.",
                    "Interface - Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}.",
                    "Agent - Paused for 60 seconds.",
                    "Agent - Resumed after sleeping for 60 seconds.",
                    "Agent - Resumed after sleeping for 60 seconds, EARLY EXIT.",
                    "Agent - Agent re-registered.",
                    "ServiceCustom - MySQL users changed.",
                    "ServiceCustom - MySQL data changed.",
                    "ServiceCustom - IIS Site Config changed.",
                    "ServiceCustom - IIS Application Pool changed.",
                    "all good",
                    "all good",
                    "all good",
                    "all good",
                    "all good",
                    "all good"
                ])
            )
            db.session.add(new_message)
        db.session.commit()
        logger.info(f"Successfully added {num} test messages to the database.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add test message data: {e}")
def add_test_data_incidents(num=15,createAlert=True):
    all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
    for i in range(1, num + 1):
        ranagent = random.choice(all_agents)
        agent_id = ranagent.agent_id
        agent_name = ranagent.agent_name
        hostname = "exampleHost"
        lastSeenTime = time.time() - ((num - i) * 100)
        incident_data = {
            "timestamp": lastSeenTime,
            "agent_id": agent_id,
            "oldStatus": random.choice([False,True]),
            "newStatus": random.choice([False,True]),
            "message": random.choice([
                "Service - Missing required package {package} for service {service}, DISARMED.",
                "Service - Service {service_name} not running, RESTORED service to START state.",
                "Service - Service {service_name} not set to automatic start, FAILED to set to automatic start.",
                "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. SUCCESSFULLY created firewall rule Magpie_Rule_{port}_{direction}_{action}.",
                "Firewall - Default {direction} policy is deny_all and no specific {direction.lower()} allow rule for port {port} exists. DISARMED, but told to create firewall rule Magpie_Rule_{port}_{direction}_{action}.",
                "Firewall - SUCCESSFULLY removed firewall rule: {rule['Name']}/{rule['DisplayName']}: {rule['Action']} {port} {rule['Direction']} on profile {rule['Profile']}.",
                "Firewall - Could not get firewall rule information due to PowerShell error.",
                "Interface - Interface {interface} was set to DOWN, RESTORED UP state.",
                "Interface - Bad system TTL set, DISARMED.",
                "Interface - Interface {interface}'s MTU was set to {old_mtu}, RESTORED new mtu {new_mtu}.",
                f"Agent - Agent {agent_name} on {hostname} moved to Stale state. Last seen {datetime.fromtimestamp(lastSeenTime).strftime('%Y-%m-%d_%H-%M-%S')}",
                "Agent - Paused for 60 seconds.",
                "Agent - Resumed after sleeping for 60 seconds.",
                "Agent - Resumed after sleeping for 60 seconds, EARLY EXIT.",
                "Agent - Agent re-registered.",
                "ServiceCustom - MySQL users changed.",
                "ServiceCustom - MySQL data changed.",
                "ServiceCustom - IIS Site Config changed.",
                "ServiceCustom - IIS Application Pool changed.",
                "Generic - Test Test Test.",
                "Generic - Test Test Test.",
                "Genericshort",
                "Genericshort"
            ]),
            "sla": random.choice([0,get_random_time_offset_epoch(90)])
        }
        create_incident(
            incident_data,
            tag=random.choice(["New", "Active", "Closed"]),
            assignee=random.choice(["Andrew", "James", "Max", "Windows", "Windows", "Linux", "Linux", "", "", "", ""]),
            createAlert=createAlert
        )
    logger.info(f"Successfully added {num} test incidents to the database.")
def add_test_data_incidents_custom(num=5,createAlert=True):
    all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
    for i in range(1, num + 1):
        agent_id = random.choice(all_agents).agent_id
        incident_data = {
            "timestamp": time.time() - ((num - i) * 100),
            "agent_id":agent_id,
            "oldStatus": random.choice([False,True]),
            "newStatus": random.choice([False,True]),
            "message": random.choice([
                "IR - Investigate suspicious sign-in activity on {hostname} / {ipaddress}.",
                "IR - Write report on Doubletap scheduled task.",
                "Inject - Implement HTTPS for {check} scorecheck on {hostname} / {ipaddress} by {time}.",
                "Uptime - Fix failed {check} scorecheck on {hostname} / {ipaddress}.",
                "Server - User Added With Username {username} and Role {role} by User {current_user.id}"
            ]),
            "sla": random.choice([0,get_random_time_offset_epoch(90)])
        }
        create_incident(
            incident_data,
            tag=random.choice(["New", "Active", "Closed"]),
            assignee=random.choice(["Andrew", "James", "Max", "Windows", "Windows", "Linux", "Linux", "", "", "", ""]),
            createAlert=createAlert
        )
    logger.info(f"Successfully added {num} test custom incidents to the database.")
def add_test_data_auth_records(num=10):
    try:
        all_agents = Agent.query.filter(Agent.agent_id != 'custom').all()
        all_messages = Message.query.all()
        if not all_agents or not all_messages:
            logger.error("Cannot add AuthRecords: Agents or Messages tables are empty.")
            return
        for i in range(1, num + 1):
            parent_message = random.choice(all_messages)
            parent_agent_id = parent_message.agent_id
            user = random.choice(["root", "admin", "nobody", "www-data", "db_user", "malicious_actor", "service_acct"])
            login_type = random.choice(["ssh-password", "ssh-key", "tty", "sudo-attempt"])
            srcip = random.choice([
                "192.168.1.50", "10.0.0.15", "172.16.5.22", 
                "45.33.22.11", "185.22.33.44",              
                "2001:db8:3333:4444:5555:6666:7777:8888"    
            ])
            successful = random.choice([True, False, False, False]) 
            timestamp = parent_message.timestamp + random.randint(1, 10) 
            possible_notes = [
                "User in malicious_users list.",
                "Multiple failed attempts from this IP detected.",
                "Successful login from unauthorized subnet.",
                "Source IP matches known botnet signature.",
                "Unusual login time for this user account.",
                None
            ]
            new_record = AuthRecord(
                message_id=parent_message.message_id,
                agent_id=parent_agent_id,
                user=user,
                login_type=login_type,
                srcip=srcip,
                successful=successful,
                timestamp=timestamp,
                notes=random.choice(possible_notes) if not successful else "Successful login audit."
            )
            db.session.add(new_record)
        db.session.commit()
        logger.info(f"Successfully added {num} test auth records to the database.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add test auth record data: {e}")
def add_test_data_auth_config():
    try:
        test_ips = [
            ("192.168.1.50", "LEGITIMATE"),
            ("10.0.0.15", "LEGITIMATE"),
            ("172.16.5.22", "LEGITIMATE"),
            ("45.33.22.11", "MALICIOUS"),
            ("185.22.33.44", "MALICIOUS"),
            ("2001:db8:3333:4444:5555:6666:7777:8888", "MALICIOUS")
        ]
        test_users = [
            ("root", "MALICIOUS"),
            ("admin", "LEGITIMATE"),
            ("nobody", "LEGITIMATE"),
            ("www-data", "LEGITIMATE"),
            ("db_user", "LEGITIMATE"),
            ("malicious_actor", "MALICIOUS"),
            ("service_acct", "LEGITIMATE")
        ]
        config_items = []
        for val, disp in test_ips:
            config_items.append({'val': val, 'type': 'IP', 'disp': disp})
        for val, disp in test_users:
            config_items.append({'val': val, 'type': 'USER', 'disp': disp})
        added_count = 0
        for item in config_items:
            exists = AuthConfig.query.filter_by(entity_value=item['val']).first()
            if not exists:
                new_entry = AuthConfig(
                    entity_value=item['val'],
                    entity_type=item['type'],
                    disposition=item['disp']
                )
                db.session.add(new_entry)
                added_count += 1
        db.session.commit()
        logger.info(f"Successfully added {added_count} entries to AuthConfig.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to populate AuthConfig test data: {e}")
def run_git(args, cwd=GIT_PROJECT_ROOT):
    try:
        cmd = ["git", "-c", "http.sslVerify=false"] + args
        result = subprocess.run(
            cmd, 
            cwd=cwd, 
            capture_output=True, 
            text=True, 
            shell=(platform.system() == "Windows")
        )
        return result
    except Exception as E:
        logger.error(f"run_git: error when executing ({['git', '-c', 'http.sslVerify=false'] + args}): {E}")
        return "" 
def hash_id(*args):
    combined = "|".join(map(str, args))
    return hashlib.sha256(combined.encode("utf-8")).hexdigest() 
def create_incident(messageDict,tag="New",assignee="",createAlert=True):
    try:
        new_incident = Incident(
            timestamp=messageDict["timestamp"],
            agent_id=messageDict["agent_id"],
            tag=tag,
            oldStatus=messageDict["oldStatus"],
            newStatus=messageDict["newStatus"],
            message=messageDict["message"],
            assignee=assignee,
            sla=messageDict["sla"]
        )
        db.session.add(new_incident)
        db.session.commit()
        incident_id = new_incident.incident_id
    except Exception as e:
        logger.error(f"create_incident(): Error creating incident: {e}")
        db.session.rollback() 
        return
    agent_id = new_incident.agent_id
    """
    try:
        # Check if the incident message indicates a pause
        if new_incident.message.lower().split(" - ")[1].split(" ")[0] == "paused":
            # Retrieve the Agent record using the primary key
            agent = db.session.get(Agent,agent_id)
            if agent:
                pattern = r'(\\d+)\\s*(?=seconds\\b)' # remove extra slashes if this is uncommented
                match = re.search(pattern, new_incident.message)
                if match:
                    seconds = int(match.group(1))
                    # Update the database record directly
                    agent.pausedUntil = int(time.time()) + seconds
                    db.session.commit()
                else:
                    # logger.error(f"/create_incident - cannot parse seconds attribute...")
                    print(f"create_incident(): Cannot parse seconds in pause incident for Agent {agent_id}.")         
    except Exception as E:
        # This catches errors during the pause update, often due to 
        # messages not following the expected format.
        db.session.rollback() 
        # logger.debug(f"Non-standard incident message. Skipping pause update: {E}")
        pass 
    """
    if createAlert:
        try:
            new_task = WebhookQueue(incident_id=new_incident.incident_id)
            db.session.add(new_task)
            db.session.commit()
        except Exception as E:
            logger.error(f"create_incident(): Could not queue webhook in DB: {E}")
    return
def clean_and_join_path(path_string):
    path_parts = re.split(r'[\\/]', path_string)
    path_parts = [part for part in path_parts if part]
    return os.path.join(*path_parts)
def get_git_stats(db,repos_root=os.path.join(GIT_PROJECT_ROOT,"")):
    results = []
    for repo_folder in os.listdir(repos_root):
        repo_path = os.path.join(repos_root, repo_folder)
        if not os.path.isdir(repo_path):
            continue
        agent_id_str = repo_folder.replace(".git", "")
        agent = db.session.query(Agent).filter_by(agent_id=agent_id_str).first()
        for branch in ["good", "bad"]:
            try:
                repo_path = os.path.join(GIT_PROJECT_ROOT, repo_folder)
                cp_commit = run_git(["show", "-s", "--format=%s|%at", branch], repo_path)
                commit_raw = cp_commit.stdout.strip() 
                if not commit_raw:
                    continue
                name, timestamp = commit_raw.split('|')
                cp_diff = run_git(["diff", f"{branch}^!", "--summary"], repo_path)
                diff_output = cp_diff.stdout
                added = diff_output.count("create mode")
                deleted = diff_output.count("delete mode")
                cp_total = run_git(["diff", f"{branch}^!", "--name-only"], repo_path)
                total_files = len(cp_total.stdout.splitlines())
                modified = total_files - (added + deleted)
                entry = {
                    "repo_name": repo_folder,
                    "branch": branch,
                    "agent_name": agent.agent_name if agent else "UNK",
                    "hostname": agent.hostname if agent else "UNK",
                    "ip": agent.ip if agent else "UNK",
                    "latest_commit_name": name,
                    "latest_commit_time": datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S'),
                    "diffs": {
                        "files_added": added,
                        "files_deleted": deleted,
                        "files_modified": modified
                    }
                }
                results.append(entry)
            except Exception as e:
                logger.warning(f"Failed to process branch {branch} in {repo_folder}: {e}")
                continue
    return results
def find_incident(incidents, criteria, newest=False):
    def matches(incident):
        for key, required in criteria.items():
            value = incident.get(key)
            if isinstance(required, (tuple, list)):
                if value not in required:
                    return False
            else:
                if value != required:
                    return False
        return True
    candidates = [
        (iid, data)
        for iid, data in incidents.items()
        if matches(data)
    ]
    if not candidates:
        return None
    key_fn = (lambda x: -x[1]["timestamp"]) if newest else (lambda x: x[1]["timestamp"])
    selected_iid, _ = min(candidates, key=key_fn)
    return selected_iid
def find_incident_db(criteria, newest=False):
    query = Incident.query
    for key, required_value in criteria.items():
        column = getattr(Incident, key, None)
        if column is None:
            logger.warning(f"find_incident_db(): Warning: Criteria key '{key}' does not match a column in Incident model.")
            return None 
        if isinstance(required_value, (tuple, list)):
            query = query.filter(column.in_(required_value))
        else:
            query = query.filter(column == required_value)
    if newest:
        query = query.order_by(Incident.timestamp.desc())
    else:
        query = query.order_by(Incident.timestamp.asc())
    selected_incident = query.first()
    if selected_incident:
        return selected_incident.incident_id
    else:
        return None
def is_safe_path(next_url: str) -> bool:
    if not next_url:
        return False
    next_url = unquote_plus(next_url)
    parsed = urlparse(next_url)
    return (parsed.scheme == "" and parsed.netloc == "" and next_url.startswith("/"))