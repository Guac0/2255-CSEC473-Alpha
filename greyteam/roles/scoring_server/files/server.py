from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import time
import re
import os
import random
import threading, time
import json
from collections import deque
import base64
from urllib.parse import urlparse, unquote_plus
import urllib.request
import urllib.error
import math
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import class_mapper
from sqlalchemy import func, event
import ipaddress

from shared import (
CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE, CREATE_TEST_DATA,
DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, SECRET_KEY, 
setup_logging)
from models import (
db, AuthToken, WebUser, WebhookQueue, Host,
ScoringUser, ScoringUserList, Service, ScoringHistory, ScoringCriteria, ScoringTeams
)
from data import create_db_tables

# =================================
# ==== INITIALIZE VARS/SETTINGS ===
# =================================

# === Set Flask Config ===
SQLALCHEMY_DATABASE_URI = f'sqlite:///{SAVEFILE}'
app = Flask(__name__)
app.config['SECRET_KEY'] = CONFIG["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Silence the deprecation warning
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
# Enable write ahead logging
# TODO app.context
#@event.listens_for(db.engine, "connect")
#def set_sqlite_pragma(dbapi_connection, connection_record):
#    cursor = dbapi_connection.cursor()
#    cursor.execute("PRAGMA journal_mode=WAL")
#    cursor.execute("PRAGMA synchronous=NORMAL")
#    cursor.close()

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

db.init_app(app)
logger = setup_logging("server")

# =================================
# ======= UTILITY FUNCTIONS =======
# =================================

# === DATABASE ====

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

def get_scoring_data_latest():
    try:
        # Find latest round with all services listed
        total_services = db.session.query(func.count(Service.id)).scalar()
        if total_services == 0:
            return [], 0
        recent_round_query = db.session.query(ScoringHistory.round)\
            .group_by(ScoringHistory.round)\
            .having(func.count(ScoringHistory.id) == total_services)\
            .order_by(ScoringHistory.round.desc())\
            .first()

        if not recent_round_query:
            logger.info("/get_scoring_data_latest - No complete scoring rounds found.")
            return [], 0

        latest_round = recent_round_query[0]

        # Fetch all data for the round using joins
        results = db.session.query(
            Host.hostname,
            Host.ip,
            Host.os,
            ScoringTeams.team_name,
            ScoringHistory.message,
            Service.scorecheck_name
        ).join(Host, ScoringHistory.host_id == Host.id)\
         .join(ScoringTeams, ScoringHistory.value == ScoringTeams.id)\
         .filter(ScoringHistory.round == latest_round)\
         .all()

        # Convert to list of dicts and sort by ip
        host_list = [
            {
                "hostname": r.hostname,
                "ip": r.ip,
                "os": r.os,
                "team": r.team_name,
                "message": r.message,
                "service": r.scorecheck_name
            } for r in results
        ]
        host_list.sort(key=lambda x: ipaddress.ip_address(x['ip']))

        return host_list, latest_round

    except Exception as e:
        logger.warning(f"/get_scoring_data_latest: Exception - {e}")
        return [], 0
    
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

@app.route("/scoreboard")
@login_required
def page_scoreboard():
    logger.info(f"/scoreboard - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("scoreboard.html")

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

        task = WebhookQueue(
            title="Web User Added",
            content=f"Web User Added With Username {username} and Role {role} by User {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

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

        db.session.delete(user_to_delete)
        db.session.commit()

        task = WebhookQueue(
            title="Web User Deleted",
            content=f"Web User Deleted With Username {username} and Role {user_role} by User {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()
        
        logger.info(f"/delete_user - Successful connection from {current_user.id} at {request.remote_addr}. Deleting user {username} with role {user_role}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/delete_user - Database error: {e}")
        return jsonify({"error": "Database error while deleting user"}), 500

@app.route("/update_password", methods=["POST"])
@login_required
def update_password():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not all([username,password]):
        logger.warning(f"/update_password - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[username]}")
        return "Missing data", 400
    
    if current_user.role != "admin":
        if username != current_user.id:
            logger.warning(f"/update_password - Failed connection from {current_user.id} at {request.remote_addr} - cannot change other user. Full details: {[username]}")
            return "Target username must be the same as current username", 400
    
    user_to_update = WebUser.query.filter_by(username=username).first()

    try:
        user_role = user_to_update.role
        user_to_update.password = generate_password_hash(password)
        db.session.commit()

        task = WebhookQueue(
            title="Web User Password Changed",
            content=f"Web User Password Changed for User {user_to_update.username} by User {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()
        
        logger.info(f"/update_password - Successful connection from {current_user.id} at {request.remote_addr}. Changing password for user {username}.")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/update_password - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": "Database error while updating user"}), 500

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
        
        task = WebhookQueue(
            title="Token Added",
            content=f"Token ({new_token.token[:2]}...{new_token.token[-2:]}) Added by User {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

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
        
        db.session.delete(token_to_delete)
        db.session.commit()

        task = WebhookQueue(
            title="Token Deleted",
            content=f"Token {token_to_delete.token} Deleted by User {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/delete_token - Successful connection from {current_user.id} at {request.remote_addr}. Deleting token {token} that was added by {added_by} at {timestamp}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"/delete_token - Database error: {e}")
        return jsonify({"error": "Database error while deleting token"}), 500

# --- Hosts Endpoints ---

@app.route("/add_host", methods=["POST"])
def add_host():
    data = request.json
    hostname = data.get("hostname")
    ip = data.get("ip")
    os = data.get("os")

    if not all([hostname, ip, os]):
        logger.warning(f"/add_host - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {data}")
        return "Missing data", 400

    try:
        new_host = Host(hostname=hostname, ip=ip, os=os)
        db.session.add(new_host)
        db.session.commit()

        task = WebhookQueue(
            title="Host Added",
            content=f"Host Added with Hostname {hostname}, IP {ip}, OS {os} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/add_host - Successful connection from {current_user.id} at {request.remote_addr}. Added host {hostname} with IP {ip}")
        return jsonify({"status": "ok", "id": new_host.id})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_host - Database error from {current_user.id} at {request.remote_addr}: {e}. Data: {data}")
        return jsonify({"error": "Database error while adding host"}), 500

@app.route("/remove_host", methods=["POST"])
def remove_host():
    data = request.json
    host_id = data.get("id")

    if not host_id:
        logger.warning(f"/remove_host - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {data}")
        return "Missing data", 400

    host_to_delete = Host.query.get(host_id)
    if not host_to_delete:
        logger.warning(f"/remove_host - Failed connection from {current_user.id} at {request.remote_addr} - host not found. Full details: {data}")
        return "Host not found", 400

    try:
        host_name = host_to_delete.hostname
        ip = host_to_delete.ip
        os = host_to_delete.os
        
        # Note: Cascading deletes should be handled by DB relationships to maintain referential integrity
        db.session.delete(host_to_delete)
        db.session.commit()

        task = WebhookQueue(
            title="Host Deleted",
            content=f"Host Deleted with Hostname {host_name}, IP {ip}, OS {os} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/remove_host - Successful connection from {current_user.id} at {request.remote_addr}. Deleted host {host_name} (ID: {host_id})")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/remove_host - Database error from {current_user.id} at {request.remote_addr}: {e}. Data: {data}")
        return jsonify({"error": "Database error while deleting host"}), 500

@app.route("/update_host_ip", methods=["POST"])
def update_host_ip():
    data = request.json
    host_id = data.get("id")
    new_ip = data.get("ip")

    if not all([host_id, new_ip]):
        logger.warning(f"/update_host_ip - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {data}")
        return "Missing data", 400

    host = Host.query.get(host_id)
    if not host:
        logger.warning(f"/update_host_ip - Failed connection from {current_user.id} at {request.remote_addr} - host not found. Full details: {data}")
        return "Host not found", 400

    try:
        old_ip = host.ip
        host.ip = new_ip
        db.session.commit()

        task = WebhookQueue(
            title="Host IP Modified",
            content=f"Host {host.hostname}'s IP changed from {old_ip} tp {new_ip} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/update_host_ip - Successful connection from {current_user.id} at {request.remote_addr}. Updated {host.hostname} IP from {old_ip} to {new_ip}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/update_host_ip - Database error from {current_user.id} at {request.remote_addr}: {e}. Data: {data}")
        return jsonify({"error": "Database error while updating IP"}), 500

@app.route("/get_hosts", methods=["GET"])
def get_hosts():
    try:
        hosts = Host.query.all()
        host_list = [host.to_dict() for host in hosts]
        
        logger.info(f"/get_hosts - Successful connection from {current_user.id} at {request.remote_addr}. Returned {len(host_list)} hosts.")
        return jsonify(host_list)
    except Exception as e:
        logger.error(f"/get_hosts - Database error from {current_user.id}: {e}")
        return jsonify({"error": "Database error while retrieving hosts"}), 500

# --- ScoringUser Endpoints ---

@app.route("/add_scoring_user", methods=["POST"])
def add_scoring_user():
    data = request.json
    host_id = data.get("host_id")
    username = data.get("username")
    password = data.get("password")

    if not all([host_id, username, password]):
        logger.warning(f"/add_scoring_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {data}")
        return "Missing data", 400

    try:
        new_user = ScoringUser(
            host_id=host_id,
            username=username,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()

        task = WebhookQueue(
            title="Scoring User Added",
            content=f"Scoring User added for host_id {host_id} with username {username} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/add_scoring_user - Successful connection from {current_user.id} at {request.remote_addr}. Added user {username} to host {host_id}")
        return jsonify({"status": "ok", "id": new_user.id})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_scoring_user - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}. Data: {data}")
        return jsonify({"error": "Database error while adding scoring user"}), 500

@app.route("/remove_scoring_user", methods=["POST"])
def remove_scoring_user():
    data = request.json
    user_id = data.get("id")

    if not all([user_id]):
        logger.warning(f"/remove_scoring_user - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[user_id]}")
        return "Missing data", 400

    user_to_delete = ScoringUser.query.get(user_id)
    if not user_to_delete:
        logger.warning(f"/remove_scoring_user - Failed connection from {current_user.id} at {request.remote_addr} - user not found. Full details: {[user_id]}")
        return "User not found", 400

    try:
        username = user_to_delete.username
        host_id = user_to_delete.host_id
        
        db.session.delete(user_to_delete)
        db.session.commit()

        task = WebhookQueue(
            title="Scoring User Deleted",
            content=f"Scoring User deleted for host_id {host_id} with username {username} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/remove_scoring_user - Successful connection from {current_user.id} at {request.remote_addr}. Deleted user {username} (ID: {user_id}) from host {host_id}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/remove_scoring_user - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": "Database error while deleting user"}), 500

@app.route("/update_scoring_user_pwd", methods=["POST"])
def update_scoring_user_pwd():
    data = request.json
    user_id = data.get("id")
    new_password = data.get("password")

    if not all([user_id, new_password]):
        logger.warning(f"/update_scoring_user_pwd - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[user_id]}")
        return "Missing data", 400

    user = ScoringUser.query.get(user_id)
    if not user:
        logger.warning(f"/update_scoring_user_pwd - Failed connection from {current_user.id} at {request.remote_addr} - user not found. Full details: {[user_id]}")
        return "User not found", 400

    try:
        user.password = new_password
        db.session.commit()

        task = WebhookQueue(
            title="Scoring User Password Changed",
            content=f"Scoring User password changed for host_id {user.host_id} with username {user.username} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/update_scoring_user_pwd - Successful connection from {current_user.id} at {request.remote_addr}. Updated password for user {user.username} (ID: {user_id})")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/update_scoring_user_pwd - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": "Database error while updating password"}), 500

@app.route("/get_scoring_users", methods=["GET"])
def get_scoring_users():
    """Returns all users without passwords for general display."""
    try:
        users = ScoringUser.query.all()
        # Custom dict comprehension to exclude password
        user_list = [{"id": u.id, "host_id": u.host_id, "username": u.username} for u in users]
        
        logger.info(f"/get_scoring_users - Successful connection from {current_user.id} at {request.remote_addr}. Returned {len(user_list)} users.")
        return jsonify(user_list)
    except Exception as e:
        logger.error(f"/get_scoring_users - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": "Database error"}), 500

@app.route("/get_scoring_users_with_pwd", methods=["GET"])
def get_scoring_users_with_pwd():
    """Returns all users including passwords"""
    try:
        users = ScoringUser.query.all()
        user_list = [u.to_dict() for u in users]
        
        logger.info(f"/get_scoring_users_with_pwd - Successful connection from {current_user.id} at {request.remote_addr}. SENSITIVE DATA ACCESSED.")
        return jsonify(user_list)
    except Exception as e:
        logger.error(f"/get_scoring_users_with_pwd - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": "Database error"}), 500

# --- ScoringHistory Endpoints ---

@app.route("/get_scoring_latest", methods=["GET"])
def get_scoring_latest():
    try:
        # Get the highest round number currently in the database
        latest_round = db.session.query(func.max(ScoringHistory.round)).scalar()
        
        if latest_round is None:
            logger.info(f"/get_scoring_latest - Success from {current_user.id} at {request.remote_addr}. No history found.")
            return jsonify([])

        # Fetch all service results for that specific round
        results = ScoringHistory.query.filter_by(round=latest_round).all()
        history_list = [h.to_dict() for h in results]

        logger.info(f"/get_scoring_latest - Success from {current_user.id} at {request.remote_addr}. Round: {latest_round}, Count: {len(history_list)}")
        return jsonify(history_list)
    except Exception as e:
        logger.error(f"/get_scoring_latest - Failed request from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": "Database error while fetching latest scores"}), 500

@app.route("/get_scoring_host", methods=["POST"])
def get_scoring_host():
    data = request.json
    host_id = data.get("host_id")
    start_round = data.get("start_round")
    end_round = data.get("end_round")

    if not host_id:
        logger.warning(f"/get_scoring_host - Failed request from {current_user.id} at {request.remote_addr} - missing host_id. Full details: {data}")
        return "Missing host_id", 400

    try:
        query = ScoringHistory.query.filter_by(host_id=host_id)
        
        if start_round is not None:
            query = query.filter(ScoringHistory.round >= start_round)
        if end_round is not None:
            query = query.filter(ScoringHistory.round <= end_round)
            
        results = query.order_by(ScoringHistory.round.desc()).all()
        history_list = [h.to_dict() for h in results]

        logger.info(f"/get_scoring_host - Success from {current_user.id} at {request.remote_addr}. Host: {host_id}, Count: {len(history_list)}")
        return jsonify(history_list)
    except Exception as e:
        logger.error(f"/get_scoring_host - Failed request from {current_user.id} at {request.remote_addr} - Database error: {e}. Data: {data}")
        return jsonify({"error": "Database error while fetching host history"}), 500

@app.route("/get_scoring_service", methods=["POST"])
def get_scoring_service():
    data = request.json
    service_id = data.get("service_id")
    start_round = data.get("start_round")
    end_round = data.get("end_round")

    if not service_id:
        logger.warning(f"/get_scoring_service - Failed request from {current_user.id} at {request.remote_addr} - missing service_id. Full details: {data}")
        return "Missing service_id", 400

    try:
        query = ScoringHistory.query.filter_by(service_id=service_id)
        
        if start_round is not None:
            query = query.filter(ScoringHistory.round >= start_round)
        if end_round is not None:
            query = query.filter(ScoringHistory.round <= end_round)
            
        results = query.order_by(ScoringHistory.round.desc()).all()
        history_list = [h.to_dict() for h in results]

        logger.info(f"/get_scoring_service - Success from {current_user.id} at {request.remote_addr}. Service: {service_id}, Count: {len(history_list)}")
        return jsonify(history_list)
    except Exception as e:
        logger.error(f"/get_scoring_service - Failed request from {current_user.id} at {request.remote_addr} - Database error: {e}. Data: {data}")
        return jsonify({"error": "Database error while fetching service history"}), 500

@app.route("/get_scoring_round", methods=["POST"])
def get_scoring_round():
    data = request.json
    round_num = data.get("round")
    start_round = data.get("start_round")
    end_round = data.get("end_round")

    # Validate that we have either a specific round or an interval
    if round_num is None and (start_round is None and end_round is None):
        logger.warning(f"/get_scoring_round - Failed from {current_user.id} - missing round data. Full details: {data}")
        return "Missing round data", 400

    try:
        query = ScoringHistory.query
        
        if round_num is not None:
            query = query.filter_by(round=round_num)
        else:
            if start_round is not None:
                query = query.filter(ScoringHistory.round >= start_round)
            if end_round is not None:
                query = query.filter(ScoringHistory.round <= end_round)

        results = query.all()
        history_list = [h.to_dict() for h in results]

        logger.info(f"/get_scoring_round - Success from {current_user.id} at {request.remote_addr}. Data: {data}, Count: {len(history_list)}")
        return jsonify(history_list)
    except Exception as e:
        logger.error(f"/get_scoring_round - Failed request from {current_user.id} at {request.remote_addr} - Database error: {e}. Data: {data}")
        return jsonify({"error": "Database error while fetching round data"}), 500

@app.route("/set_scoring", methods=["POST"])
def set_scoring():
    data = request.json
    service_id = data.get("service_id")
    host_id = data.get("host_id")
    round_num = data.get("round")
    value = data.get("value")

    if None in [service_id, host_id, round_num, value]:
        logger.warning(f"/set_scoring - Failed request from {current_user.id} at {request.remote_addr} - missing data. Full details: {data}")
        return "Missing data", 400

    try:
        # Check if a record already exists for this service and round to avoid duplicates
        existing_record = ScoringHistory.query.filter_by(service_id=service_id, round=round_num).first()
        
        if existing_record:
            existing_record.value = value
            existing_record.host_id = host_id
            msg = f"Updated round {round_num} for service {service_id}"
        else:
            new_score = ScoringHistory(
                service_id=service_id,
                host_id=host_id,
                round=round_num,
                value=value
            )
            db.session.add(new_score)
            msg = f"Created round {round_num} for service {service_id}"

        db.session.commit()

        task = WebhookQueue(
            title="Scoring Modified",
            content=f"Scoring Round {round_num} for service id {service_id} to be {value} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/set_scoring - Successful connection from {current_user.id} at {request.remote_addr}. {msg}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/set_scoring - Failed request from {current_user.id} at {request.remote_addr} - Database error: {e}. Data: {data}")
        return jsonify({"error": "Database error while setting score"}), 500
    
# --- ScoringCriteria Endpoints ---

@app.route("/set_criteria", methods=["POST"])
def set_criteria():
    """Wipes existing criteria for a service and sets new ones."""
    data = request.json
    service_id = data.get("service_id")
    criteria_list = data.get("criteria") # Expecting list of dicts: [{content, location}, ...]

    if not all([service_id, criteria_list]):
        logger.warning(f"/set_criteria - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {data}")
        return "Missing data", 400

    try:
        # Remove existing criteria for this service
        ScoringCriteria.query.filter_by(service_id=service_id).delete()
        
        for item in criteria_list:
            new_crit = ScoringCriteria(
                service_id=service_id,
                host_id=item.get("host_id"),
                content=item.get("content"),
                location=item.get("location")
            )
            db.session.add(new_crit)
        
        db.session.commit()

        task = WebhookQueue(
            title="Scoring Criteria Reset",
            content=f"Scoring Criteria Reset for service id {service_id} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/set_criteria - Successful connection from {current_user.id} at {request.remote_addr}. Data: {data}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/set_criteria - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/add_criteria", methods=["POST"])
def add_criteria():
    data = request.json
    host_id = data.get("host_id")
    service_id = data.get("service_id")
    content = data.get("content")
    location = data.get("location")

    if not all([host_id, service_id, content, location]):
        logger.warning(f"/add_criteria - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {data}")
        return "Missing data", 400

    try:
        new_criteria = ScoringCriteria(
            host_id=host_id,
            service_id=service_id,
            content=content,
            location=location
        )
        db.session.add(new_criteria)
        db.session.commit()

        task = WebhookQueue(
            title="Scoring Criteria Added",
            content=f"Scoring Criteria added for host_id {host_id} and service_id {service_id} with location {location} and content {content[:10]}... by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/add_criteria - Successful connection from {current_user.id} at {request.remote_addr}. Added criteria ID {new_criteria.id}")
        return jsonify({"status": "ok", "id": new_criteria.id})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_criteria - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": "Database error"}), 500

@app.route("/remove_criteria", methods=["POST"])
def remove_criteria():
    data = request.json
    criteria_id = data.get("id")

    if not criteria_id:
        logger.warning(f"/remove_criteria - Failed connection from {current_user.id} at {request.remote_addr} - missing ID. Full details: {data}")
        return "Missing ID", 400

    criteria = ScoringCriteria.query.get(criteria_id)
    if not criteria:
        logger.warning(f"/remove_criteria - Failed connection from {current_user.id} - criteria {criteria_id} not found.")
        return "Criteria not found", 404

    try:
        host_id = criteria.host_id
        service_id = criteria.service_id
        content = criteria.content
        location = criteria.location
        db.session.delete(criteria)
        db.session.commit()

        task = WebhookQueue(
            title="Scoring Criteria Deleted",
            content=f"Scoring Criteria deleted for host_id {host_id} and service_id {service_id} with content {content[:10]}... and location {location} by user {current_user.id}"
        )
        db.session.add(task)
        db.session.commit()

        logger.info(f"/remove_criteria - Successful connection from {current_user.id} at {request.remote_addr}. Removed ID {criteria_id}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/remove_criteria - Failed connection from {current_user.id} at {request.remote_addr} - Database error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/update_criteria_content", methods=["POST"])
def update_criteria_content():
    # TODO webhook
    data = request.json
    criteria_id = data.get("id")
    new_content = data.get("content")

    if not all([criteria_id, new_content]):
        logger.warning(f"/update_criteria_content - Failed connection from {current_user.id} - missing data: {data}")
        return "Missing data", 400

    criteria = ScoringCriteria.query.get(criteria_id)
    if not criteria:
        return "Criteria not found", 404

    try:
        criteria.content = new_content
        db.session.commit()
        
        logger.info(f"/update_criteria_content - User {current_user.id} updated content for ID {criteria_id}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/update_criteria_content - Failed connection from {current_user.id} at {request.remote_addr} - Error: {e}")
        return jsonify({"error": "Update failed"}), 500

@app.route("/update_criteria_locations", methods=["POST"])
def update_criteria_locations():
    # TODO webhook
    data = request.json
    criteria_id = data.get("id")
    new_location = data.get("location")

    if not all([criteria_id, new_location]):
        logger.warning(f"/update_criteria_locations - Failed connection from {current_user.id} - missing data: {data}")
        return "Missing data", 400

    criteria = ScoringCriteria.query.get(criteria_id)
    if not criteria:
        return "Criteria not found", 404

    try:
        criteria.location = new_location
        db.session.commit()
        
        logger.info(f"/update_criteria_locations - User {current_user.id} updated location for ID {criteria_id}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/update_criteria_locations - Failed connection from {current_user.id} at {request.remote_addr} - Error: {e}")
        return jsonify({"error": "Update failed"}), 500

# =================================
# ============= MAIN ==============
# =================================

logger.info(f"Starting server on {HOST}:{PORT}")
with app.app_context:
    create_db_tables(logger)

def start_server():
    app.run(host=HOST, port=PORT, ssl_context='adhoc', use_reloader=False, debug=False)

if __name__ == "__main__":
    pass
    #with app.app_context:
    #    create_db_tables()

    # Start threads before test data to avoid delays
    #threading.Thread(target=webhook_main, daemon=True).start()

    # Start main app. Do not put any code below this line. Comment out when using gunicorn
    #start_server()