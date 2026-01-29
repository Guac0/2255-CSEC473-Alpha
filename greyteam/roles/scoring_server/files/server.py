from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import time
import re
import os
import random
import atexit, signal, sys
import threading, time
import json
from collections import deque
import base64
from urllib.parse import urlparse, unquote_plus
import urllib.request
import urllib.error
import math
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import class_mapper
from sqlalchemy import func, event
import subprocess
from pathlib import Path
import platform
from flask_session import Session

CONFIG_DEFAULTS = {
    "HOST": "0.0.0.0",
    "PORT": 8080,
    "PUBLIC_URL": "https://{HOST}:{PORT}",
    "LOGFILE": "log_{timestamp}.txt",
    "SAVEFILE": "save_{timestamp}.db",
    "SECRET_KEY": "changemeplease",
    "STALE_TIME": 300,
    "DEFAULT_WEBHOOK_SLEEP_TIME": 0.25,
    "MAX_WEBHOOK_MSG_PER_MINUTE": 50,
    "WEBHOOK_URL": "",
    "AGENT_AUTH_TOKENS": {
        "testtoken": { 
            "added_by": "default"
        }
    },
    "WEBGUI_USERS": {
        "admin": {"password": "admin", "role": "admin"},
        "analyst": {"password": "analyst", "role": "analyst"},
        "guest": {"password": "guest", "role": "guest"}
    }
}

def load_config(path):
    config = CONFIG_DEFAULTS.copy()
    badPath = False

    if os.path.exists(path):
        with open(path, "r") as f:
            config.update(json.load(f))
    else:
        badPath = True

    # Generate timestamp once
    now = datetime.now()

    # 2. Round up to the start of the next minute
    # (Adds 1 minute and zeros out the seconds/microseconds)
    next_minute = (now + timedelta(minutes=1)).replace(second=0, microsecond=0)

    # 3. Generate the timestamp string
    timestamp = next_minute.strftime("%Y-%m-%d_%H-%M-00")

    # Replace placeholders in strings
    for key, value in config.items():
        if isinstance(value, str):
            config[key] = value.format(
                HOST=config.get("HOST"),
                PORT=config.get("PORT"),
                timestamp=timestamp
            )

    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: # intentionally not the correct logfile format
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")

    #config["PUBLIC_URL"] = f"http://{config['HOST']}:{config['PORT']}"
    #config["LOGFILE"] = f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    #config["SAVEFILE"] = f"save_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"

    return config

CONFIG = load_config("config.json") # relative to cwd!
HOST = CONFIG["HOST"]
PORT = CONFIG["PORT"]
PUBLIC_URL = CONFIG["PUBLIC_URL"]
LOGFILE = CONFIG["LOGFILE"]
SAVEFILE = CONFIG["SAVEFILE"]
DEFAULT_WEBHOOK_SLEEP_TIME = CONFIG["DEFAULT_WEBHOOK_SLEEP_TIME"]
MAX_WEBHOOK_MSG_PER_MINUTE = CONFIG["MAX_WEBHOOK_MSG_PER_MINUTE"]
WEBHOOK_URL = CONFIG["WEBHOOK_URL"]
INITIAL_AGENT_AUTH_TOKENS = CONFIG["AGENT_AUTH_TOKENS"]
INITIAL_WEBGUI_USERS = CONFIG["WEBGUI_USERS"]
SECRET_KEY = CONFIG["SECRET_KEY"]

# =================================
# ==== INITIALIZE VARS/SETTINGS ===
# =================================

# === Set Flask Config ===
SQLALCHEMY_DATABASE_URI = f'sqlite:///{SAVEFILE}'
app = Flask(__name__)
app.config['SECRET_KEY'] = CONFIG["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
db = SQLAlchemy(app) # Initialize SQLAlchemy
app.config.update(
    SESSION_COOKIE_SECURE=True, # Forces the session cookie to be sent only over HTTPS.
    SESSION_COOKIE_HTTPONLY=True, # Prevents JavaScript from accessing the session cookie
    SESSION_COOKIE_SAMESITE="Strict", # "Strict": the cookie is only sent for requests from the same site (no subdomains)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=3),
    SESSION_REFRESH_EACH_REQUEST=True, # Automatic refreshes mean that lifetime is effectively infinite! This means that users actively on the site won't get signed out, but people who close the site but not the browser and keep it closed for 1 min will have to sign in again
    
    # --- Server-Side Session Config ---
    SESSION_TYPE='sqlalchemy',
    SESSION_SQLALCHEMY=db,  # Tell it to use your existing SQLAlchemy instance
    SESSION_SQLALCHEMY_TABLE='flask_sessions', # It will create this table automatically
    SESSION_PERMANENT=True,
    SESSION_USE_SIGNER=True # Protects the session cookie from tampering
)
# Silence the deprecation warning
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Enable write ahead logging
@event.listens_for(db.engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

# === Initialize Misc Vars ===
start_time = time.time()
#last_save_time=0
TTYD_PROCESS = None
class User(UserMixin):
    def __init__(self, id, role):
        # Password is not saved here - use webgui_users.get(username)['password']
        self.id = id
        self.role = role
# See load_user() for the following
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # redirect to login page if not authenticated

# === DATABASE SETUP ===

class AuthToken(db.Model):
    __tablename__ = 'auth_tokens'
    
    token = db.Column(db.String(128), primary_key=True, nullable=False) # The token string itself
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    added_by = db.Column(db.String(128))

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    def __repr__(self):
        return f"<AuthToken {self.token[:8]}...>"

class WebUser(db.Model):
    __tablename__ = 'web_users'
    
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    password = db.Column(db.String(64), nullable=False) 
    role = db.Column(db.String(20), nullable=False) # "admin", "analyst", or "guest"

    def __repr__(self):
        return f"<WebUser {self.username} (Role: {self.role})>"

class WebhookQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.incident_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Host(db.Model):
    """
    Records each host in the network that has scored service(s) on them.
    
    Relationships:
    one:many with scoringusers
    one:many with services
    one:many with scoringcriteria
    """
    __tablename__ = 'hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    os = db.Column(db.String(32), nullable=False)

    scoringusers = db.relationship('ScoringUser', backref='host')
    services = db.relationship('Service', backref='host')
    scoringcriteria = db.relationship('ScoringCriteria', backref='host')

    def __repr__(self):
        return f"<Host {self.hostname}, IP {self.ip}, OS {self.os}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringUser(db.Model):
    """
    Records each user:password combo for each host
    Each host has a unique set of users, although some may same usernames/passwords between hosts
    
    Relationships:
    many:one with hosts
    many:many with scoringuserlists
    """
    __tablename__ = 'scoring_users'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64))

    scoringuserlists = db.relationship('ScoringUserList', backref='scoringuser')

    def __repr__(self):
        return f"<ScoringUser {self.username}@{self.hostname}>"
    def to_dict(self):
        #return {"hostname": self.hostname,"username": self.username} # no password
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringUserList(db.Model):
    """
    Maps several ScoringUsers to one ScoringCriteria instance.
    Each entry has one ScoringUser and one ScoringCriteria, but ScoringCriteria has several entries in ScoringUserList.
    
    Relationships:
    one:one with ScoringUser
    many:one with ScoringCriteria
    """
    __tablename__ = 'scoring_user_lists'

    id = db.Column(db.Integer, primary_key=True)
    criteria_id = db.Column(db.Integer, db.ForeignKey('scoring_criterias.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('scoring_users.id'), nullable=False)

    def __repr__(self):
        return f"<ScoringUserList Index: {self.index}, User: {self.username}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Service(db.Model):
    """
    Records each Service that is scored.
    Scoring criteria(s) is recorded in ScoringCriteria, and results in ScoringHistory.

    Relationships:
    one:one with ScoringHistory
    one:many with ScoringCriteria
    """
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    scorecheck_name = db.Column(db.String(64), index=True, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    
    scoringhistories = db.relationship('ScoringHistory', backref='service')
    scoringcriterias = db.relationship('ScoringCriteria', backref='service')

    def __repr__(self):
        return f"<Service Scorecheck: {self.scorecheck_name}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringHistory(db.Model):
    """
    Records the scoring state for each round. One round occurs every minute.
    During each round, the scoring worker assesses the state of each scorecheck (online or offline)
    using the criteria in ScoringCriteria and loads each service's result into a separate entry in ScoringHistory.
    
    Relationships:
    many:one with Services
    """
    __tablename__ = 'scoring_histories'

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), index=True, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), index=True, nullable=False)
    round = db.Column(db.Integer, index=True, nullable=False)
    value = db.Column(db.Integer, nullable=False)

    __table_args__ = (
        # Optimizes 'Get all services for one round'
        db.Index('idx_round_service', 'round', 'service_id'),
    )

    def __repr__(self):
        return f"<ScoringHistory Round: {self.round}, Service_id: {self.service_id}, Value: {self.value}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringCriteria(db.Model):
    """
    Records the scoring criteria for a particular service.
    A service may have multiple scoring criterias; only one needs to be satisfied for the scorecheck to succeed.

    Relationships:
    many:one with hosts
    many:one with services
    one:many with user lists
    """
    __tablename__ = 'scoring_criterias'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'))
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'))
    #userlist_index = db.Column(db.Integer, index=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(128), nullable=False)

    scoringuserlist = db.relationship('ScoringUserList', backref='scoringcriteria')

    def __repr__(self):
        return f"<ScoringCriteria Host: {self.host_id}, Scorecheck: {self.service_id}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# =================================
# ======= UTILITY FUNCTIONS =======
# =================================


def setup_logging():
    # 1. Create a logger instance
    logger = logging.getLogger(__name__)
    
    # If the logger already has handlers, don't add more (prevents duplicate entries)
    if logger.handlers:
        logger.info(f"setup_logging(): logger already exists, returning existing logger")
        return logger

    logger.setLevel(logging.INFO)

    # 2. Use ConcurrentRotatingFileHandler
    # This handles multiple processes (Gunicorn workers + Worker.py) 
    # and manages the .lock file automatically to prevent rotation crashes.
    handler = ConcurrentRotatingFileHandler(
        LOGFILE,        # LOGFILE path
        "a",              # append mode
        10 * 1024 * 1024, # maxBytes: 10MB
        10,               # backupCount: keep 10 old logs
        encoding='utf-8'
    )
    
    # 3. Define the log format
    formatter = logging.Formatter(
        '[%(asctime)s] [%(process)d] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # Note: Added [%(process)d] to the format above. 
    # This helps you identify which Gunicorn worker or background thread 
    # sent the message when debugging.
    
    handler.setFormatter(formatter)
    
    # 4. Add the handler to the logger
    logger.addHandler(handler)
    
    # Optional: Prevent logs from bubbling up to the root logger
    logger.propagate = False
    
    return logger

logger = setup_logging()
logger.info(f"Starting server on {HOST}:{PORT}")

# === DATABASE ====

def insert_initial_data():
    """
    Inserts initial configuration data (auth tokens and users) into the database.
    This should only be run after the tables have been created via db.create_all().
    """
    try:
        # --- Insert Auth Tokens ---
        for token_value, data in INITIAL_AGENT_AUTH_TOKENS.items():
            # In a real app, you would first check if the token already exists 
            # to prevent duplicates, but for a first run, direct insert is fine.
            new_token = AuthToken(
                token=token_value,
                timestamp=time.time(),
                added_by=data["added_by"]
            )
            db.session.add(new_token)

        # --- Insert Web Users ---
        for username, data in INITIAL_WEBGUI_USERS.items():
            hashed_password = generate_password_hash(data["password"])
            new_user = WebUser(
                username=username,
                password=hashed_password, # WARNING: Hash passwords in production!
                role=data["role"]
            )
            db.session.add(new_user)
        
        db.session.commit()
        logger.info("Successfully inserted initial database values.")

    except Exception as e:
        db.session.rollback()
        logger.error(f"FATAL: Failed to insert initial data into DB: {e}")

def create_db_tables():

    db_exists = os.path.exists(os.path.join("instance",SAVEFILE))
    # Use the application context to ensure Flask extensions are configured
    with app.app_context():
        # This checks the database file defined in SQLALCHEMY_DATABASE_URI.
        # If the file (server.db) doesn't exist, it creates it.
        # If the tables defined in your models don't exist, it creates them.
        db.create_all()
        if not db_exists:
            insert_initial_data()
            logger.info(f"Initialized database with initial data at {SAVEFILE}")
        else:
            logger.info(f"Initialized database at {SAVEFILE}")

def serialize_model(instance):
    """
    Generic function to convert any SQLAlchemy model instance into a dictionary.
    It iterates over the columns defined in the model's mapping and extracts their values.
    
    NOTE: This only serializes direct columns and ignores relationships.
    """
    
    # Use class_mapper to get the mapped properties of the class
    mapper = class_mapper(instance.__class__)
    
    # Dictionary comprehension to build the serialized data
    serialized_data = {}
    for column in mapper.columns:
        # Get the value using the attribute name (column.key)
        value = getattr(instance, column.key)
        
        serialized_data[column.key] = value

    return serialized_data

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

            # Fetch incident data needed for the webhook
            incident = Incident.query.get(task.incident_id)
            if not incident:
                # Cleanup if incident was deleted
                db.session.delete(task)
                db.session.commit()
                continue

            # Prepare the payload like your original code did
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

            # Send the webhook
            resp, body = discord_webhook(task.incident_id, incident_payload)

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

def discord_webhook(incident_id,incident,url=WEBHOOK_URL):
    #compare rules level to set colors of the alert
    if not url:
        return
    
    color = "5e5e5e" # unknown
    
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
        # weird format, fallback to generic color
        pass

    #data that the webhook will receive and use to display the alert in discord chat
    try:
        incident_record = db.session.get(Incident,incident_id)
        agent = db.session.get(Agent,incident_record.agent_id)
        if not agent:
            #logger.warning(f"Could not find agent {incident_obj.agent_id} for incident {incident_obj.incident_id}.")
            raise KeyError
        
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - {} Incident Created on {} for {}".format(incident["message"].split('-')[0].strip(),agent.hostname,agent.agent_name),
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            #"description": "{}\n\n[Open Dashboard]({}/incidents)".format(incident["message"],PUBLIC_URL),
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
            #"description": "{}\n\n[Open Dashboard]({}/incidents)".format(incident["message"],PUBLIC_URL),
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
        # weird data type with very short msg. should only happen with custom incidents, if any
        # Actually this probably will never get hit lol as split()[0] should always work
        payload = json.dumps({
        "embeds": [
            {
            "title": "Alert - Custom Generic Incident Created",
            "color": int(color,16),
            "description": "{}".format(incident["message"]),
            #"description": "{}\n\n[Open Dashboard]({}/incidents)".format(incident["message"],PUBLIC_URL),
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
            logger.info(f"/discord_webhook - sent message for incident {incident_id}.")

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
        logger.error(f"/discord_webhook - failed to send message for incident {incident_id}. StatusCode: {err.code}. Body: {body}.") # Headers: {err.headers}. 
        return err,body

# === LOGIN AND MISC ===

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.role != "analyst" and current_user.role != "admin" ):
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(id):
    user_record = WebUser.query.filter(WebUser.username == id).first()
    if user_record:
        return User(id, user_record.role)
    return None

def is_safe_path(next_url: str) -> bool:
    if not next_url:
        return False
    # percent-decoded already by Flask for request.args/form, but be safe:
    next_url = unquote_plus(next_url)
    parsed = urlparse(next_url)
    # allow only relative paths (no scheme/netloc)
    return (parsed.scheme == "" and parsed.netloc == "" and next_url.startswith("/"))

# === MISC ===
def get_random_time_offset_epoch(minutes_offset=30, direction="either"):
    """
    Returns a random timestamp in seconds since the epoch,
    within a specified minute offset from the current time.

    Args:
        minutes_offset (int): The maximum number of minutes for the offset.
        direction (str): "past", "future", or "either".

    Returns:
        float: A random timestamp in seconds since the epoch.
    """
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

def hash_id(*args):
    # hash any number of args so that we have a single value to use as the id that remains unique if multiple items have similar fields
    # Does not need to be secure
    combined = "|".join(map(str, args))
    encoded = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
    return encoded
    #return hashlib.sha256(f"{ip}|{hostname}".encode()).hexdigest() #sha256 hash - too complex to use on frontend

# =================================
# ========= API ENDPOINTS =========
# =================================

# === BASIC WEBSITE FUNCTIONALITY ===

@app.route("/")
@app.route("/dashboard")
@login_required
def page_dashboard():
    logger.info(f"/dashboard - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("dashboard.html")

@app.route("/management")
@login_required
@admin_required
def page_management():
    logger.info(f"management - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("management.html")

@app.route('/favicon.ico')
def favicon():
    logger.info(f"favicon.ico - Successful connection at {request.remote_addr}")
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico',mimetype='image/vnd.microsoft.icon')

@app.route('/background.jpg')
def background():
    logger.info(f"/background.jpg - Successful connection at {request.remote_addr}")
    return send_from_directory(os.path.join(app.root_path, 'static'),'background.jpg',mimetype='image/vnd.microsoft.icon')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # For GET render pass the next param to template so the form includes it
    if request.method == 'GET':
        next_param = request.args.get('next', '')
        logger.info(f"/login - Successful connection at {request.remote_addr}")
        return render_template('login.html', next=next_param)

    # POST
    username = request.form.get('username')
    password = request.form.get('password')
    next_param = request.form.get('next') or request.args.get('next') or ''

    user_record = WebUser.query.filter(WebUser.username == username).first()
    if user_record and check_password_hash(user_record.password, password):
        user_obj = User(username, user_record.role)
        login_user(user_obj)
        session.permanent = True
        logger.info(f"/login - Successful authentication for {username} from {request.remote_addr}")

        # Validate next and redirect safely
        if is_safe_path(next_param):
            return redirect(unquote_plus(next_param))
        return redirect(url_for('page_dashboard'))

    flash('Invalid username or password', 'danger')
    logger.error(f"/login - Unsuccessful connection for {username} with password {password} from {request.remote_addr}")
    return render_template('login.html', next=next_param)

@app.route('/logout')
@login_required
def logout():
    logger.info(f"/logout - Logging out user {current_user.id} at {request.remote_addr}")

    logout_user()
    return redirect(url_for('login'))

@app.route('/whoami')
@login_required
def whoami():
    logger.info(f"/whoami - Successful connection for {current_user.id} at {request.remote_addr}")
    return jsonify({"username": current_user.id, "role": current_user.role})

@app.route("/ping", methods=["POST"])
def ping():
    # Provides an endpoint for the client to check that they can reach the server fine. Does not check auth.
    logger.info(f"/ping - Successful connection from {request.remote_addr}")
    return "ok", 200

@login_required
@app.route("/ping_login", methods=["POST"])
def ping_login():
    # Provides an endpoint for the client to check that they can reach the server fine.
    logger.info(f"/ping_login - Successful connection from {current_user.id} at {request.remote_addr}")
    return "ok", 200

# === FRONTEND DISPLAY ===

@app.route("/list_users", methods=["POST"])
@login_required
@admin_required
def list_users():
    try:
        logger.info(f"/list_users - Successful connection from {current_user.id} at {request.remote_addr}")
        users = WebUser.query.all()
        user_dict = {user.username: serialize_model(user) for user in users}
        return jsonify(user_dict)
    except Exception as e:
        logger.error(f"/list_users - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve user list"}), 500

@app.route("/list_tokens", methods=["POST"])
@login_required
@admin_required
def list_tokens():
    try:
        logger.info(f"/list_tokens - Successful connection from {current_user.id} at {request.remote_addr}")
        tokens = AuthToken.query.all()
        token_dict = {token.token: serialize_model(token) for token in tokens}
        return jsonify(token_dict)
    except Exception as e:
        logger.error(f"/list_tokens - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve token list"}), 500

@app.route("/list_tokens_number", methods=["POST"])
@login_required
def list_tokens_number():
    """
    Returns the count of authentication tokens in the database.
    """
    try:
        logger.info(f"/list_tokens_number - Successful connection from {current_user.id} at {request.remote_addr}")
        
        token_count = AuthToken.query.count()
        
        return jsonify({"number": token_count})
    
    except Exception as e:
        logger.error(f"/list_tokens_number - Database error: {e}")
        return jsonify({"error": "Failed to retrieve token count"}), 500

@app.route("/list_logfile", methods=["POST"])
@login_required
@admin_required
def list_logfile(filepath=LOGFILE,lines=50):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Use deque to keep only the last 50 lines in memory
            last_lines = deque(f, maxlen=lines)
        logger.info(f"/list_logfile - Successful connection from {current_user.id} at {request.remote_addr}")
        return list(last_lines)

    except FileNotFoundError:
        logger.error(f"/list_logfile - Successful connection from {current_user.id} at {request.remote_addr}")
        return f"FileNotFound {filepath}", 400

@app.route("/save_export", methods=["POST"])
@login_required
@admin_required
def save_export(filepath=SAVEFILE):
    return jsonify({"error": "Deprecated"}), 500

    logger.info(f"/save_export - Successful connection from {current_user.id} at {request.remote_addr}")
    
    try:
        with open(filepath, "r") as f:
            state = json.load(f)

        incident = {
            "timestamp": time.time(),
            "agent_id":f"custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - Save Exported by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident)

        return state
    except FileNotFoundError:
        logger.error(f"/save_export - Successful connection from {current_user.id} at {request.remote_addr}")
        return f"FileNotFound {filepath}", 400

# === FRONTEND INTERACTION ===
    
@app.route("/add_user", methods=["POST"])
@login_required
@admin_required
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not all([username, password, role]):
        logger.warning(f"/add_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username, password, role]}")
        return "Missing data", 400
    
    if role not in ["guest","analyst","admin"]:
        logger.warning(f"/add_user - Failed connection from {current_user.id} at {request.remote_addr} - bad role value. Full details: {[username, password, role]}")
        return "Bad role value", 400

    existing_user = WebUser.query.filter_by(username=username).first()
    if existing_user:
        logger.warning(f"/add_user - Failed connection from {current_user.id} at {request.remote_addr} - bad username value, conflicts with existing user. Full details: {[username, password, role]}")
        return "New user overlaps with existing user", 400

    try:
       
        hashed_password = generate_password_hash(password)

        new_user = WebUser(
            username=username,
            password=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - User Added With Username {username} and Role {role} by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)

        logger.info(f"/add_user - Successful connection from {current_user.id} at {request.remote_addr}. Adding user {username} with role {role}")
        return jsonify({"status": "ok"})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_user - Database error: {e}")
        return jsonify({"error": "Database error while adding user"}), 500
    
@app.route("/delete_user", methods=["POST"])
@login_required
@admin_required
def delete_user():
    data = request.json
    username = data.get("username")

    if not all([username]):
        logger.warning(f"/delete_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username]}")
        return "Missing data", 400
    
    if username == current_user.id:
        logger.warning(f"/delete_user - Failed connection from {current_user.id} at {request.remote_addr} - cannot delete own user. Full details: {[username]}")
        return "Target username cannot be the same as current username", 400
    
    user_to_delete = WebUser.query.filter_by(username=username).first()
    
    if not user_to_delete:
        logger.warning(f"/delete_user - Failed connection from {current_user.id} at {request.remote_addr} - username not found. Full details: {[username]}")
        return "Bad role value", 400

    try:
        user_role = user_to_delete.role
        
        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - User Deleted With Username {username} and Role {user_role} by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)

        db.session.delete(user_to_delete)
        db.session.commit()
        
        logger.info(f"/delete_user - Successful connection from {current_user.id} at {request.remote_addr}. Deleting user {username} with role {user_role}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/delete_user - Database error: {e}")
        return jsonify({"error": "Database error while deleting user"}), 500

@app.route("/add_token", methods=["POST"])
@login_required
@admin_required
def add_token():
    data = request.json
    token = data.get("token")

    if not all([token]):
        logger.warning(f"/add_token - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[token]}")
        return "Missing data", 400
    
    token_record = AuthToken.query.filter_by(token=token).first()
    if token_record:
        logger.warning(f"/add_token - Failed connection from {current_user.id} at {request.remote_addr} - bad token value, conflicts with existing token. Full details: {[token]}")
        return "New token overlaps with existing token", 400
    
    try:
        new_token = AuthToken(
            token=token,
            timestamp=time.time(),
            added_by=current_user.id
        )
        
        db.session.add(new_token)
        db.session.commit()
        
        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - Token Added by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)

        logger.info(f"/add_token - Successful connection from {current_user.id} at {request.remote_addr}. Adding token {token}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_token - Database error: {e}")
        return jsonify({"error": "Database error while adding token"}), 500

@app.route("/delete_token", methods=["POST"])
@login_required
@admin_required
def delete_token():
    data = request.json
    token = data.get("token")

    if not all([token]):
        logger.warning(f"/delete_token - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[token]}")
        return "Missing data", 400
    
    token_to_delete = AuthToken.query.filter_by(token=token).first()
    
    if not token_to_delete:
        logger.warning(f"/delete_token - Failed connection from {current_user.id} at {request.remote_addr} - username not found. Full details: {[token]}")
        return "Bad role value", 400

    try:
        added_by = token_to_delete.added_by
        timestamp = datetime.fromtimestamp(token_to_delete.timestamp)
        
        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - Token Deleted by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)
        
        db.session.delete(token_to_delete)
        db.session.commit()

        logger.info(f"/delete_token - Successful connection from {current_user.id} at {request.remote_addr}. Deleting token {token} that was added by {added_by} at {timestamp}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/delete_token - Database error: {e}")
        return jsonify({"error": "Database error while deleting token"}), 500

# =================================
# ============= MAIN ==============
# =================================

def start_server():
    app.run(host=HOST, port=PORT, ssl_context='adhoc', use_reloader=False, debug=False)

if __name__ == "__main__":
    pass
    #create_db_tables()

    # Start threads before test data to avoid delays
    #threading.Thread(target=webhook_main, daemon=True).start()

    # Start main app. Do not put any code below this line. Comment out when using gunicorn
    start_server()