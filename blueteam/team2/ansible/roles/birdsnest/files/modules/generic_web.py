from flask_login import login_user, current_user, current_user
from flask import current_app, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import time
import os
from collections import deque
from urllib.parse import unquote_plus
from sqlalchemy import func
from sqlalchemy.orm import joinedload
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
from utilities import (
insert_initial_data, create_db_tables, serialize_model, is_safe_path,
get_random_time_offset_epoch, add_test_data_agents, add_test_data_messages, add_test_data_incidents,
add_test_data_incidents_custom, add_test_data_auth_records, add_test_data_auth_config,
run_git, hash_id, create_incident, clean_and_join_path, get_git_stats, find_incident, find_incident_db
)
logger = setup_logging("web")
def login():
    if request.method == 'GET':
        next_param = request.args.get('next', '')
        logger.info(f"/login - Successful connection at {request.remote_addr}")
        return render_template('login.html', next=next_param)
    username = request.form.get('username')
    password = request.form.get('password')
    next_param = request.form.get('next') or request.args.get('next') or ''
    user_record = WebUser.query.filter(WebUser.username == username).first()
    if user_record and check_password_hash(user_record.password, password):
        user_obj = User(username, user_record.role)
        login_user(user_obj)
        session.permanent = True
        logger.info(f"/login - Successful authentication for {username} from {request.remote_addr}")
        if is_safe_path(next_param):
            return redirect(unquote_plus(next_param))
        return redirect(url_for('page_dashboard'))
    flash('Invalid username or password', 'danger')
    logger.error(f"/login - Unsuccessful connection for {username} from {request.remote_addr}") 
    return render_template('login.html', next=next_param)
def dashboard_summary():
    try:
        now = int(time.time())
        one_hour_ago = now - 900 
        auth_config_raw = db.session.query(AuthConfig.entity_type, func.count(AuthConfig.id)).group_by(AuthConfig.entity_type).all()
        auth_record_raw = db.session.query(AuthRecord.login_type, func.count(AuthRecord.id)).group_by(AuthRecord.login_type).all()
        user_roles_raw = db.session.query(WebUser.role, func.count(WebUser.role)).group_by(WebUser.role).all()
        stats = {
            "agents": {
                "total": Agent.query.count() - 1,
                "active": Agent.query.filter_by(lastStatus=True).count() - 1,
                "stale": Agent.query.filter_by(stale=True).count() - 1,
                "paused": Agent.query.filter(Agent.pausedUntil != "0").count() - 1
            },
            "webhooks": {
                "queue_count": WebhookQueue.query.count() or 0,
                "ansible_count": AnsibleQueue.query.count() or 0,
                "agent_task_count_pending": AgentTask.query.filter_by(result="PENDING").count() or 0,
                "agent_task_count_sent": AgentTask.query.filter_by(result="SENT").count() or 0
            },
            "auth_globals": {str(c.key): bool(c.value) for c in AuthConfigGlobal.query.all()},
            "auth_configs": {str(t): count for t, count in auth_config_raw},
            "auth_records": {
                "total": AuthRecord.query.count() or 0,
                "by_type": {str(t): count for t, count in auth_record_raw},
                "recent_failed": AuthRecord.query.filter(AuthRecord.successful == False, AuthRecord.timestamp >= one_hour_ago).count() or 0,
                "recent_success": AuthRecord.query.filter(AuthRecord.successful == True, AuthRecord.timestamp >= one_hour_ago).count() or 0
            },
            "incidents": {
                "total": Incident.query.count() or 0,
                "new": Incident.query.filter_by(tag="New").count() or 0,
                "active": Incident.query.filter_by(tag="Active").count() or 0,
                "closed": Incident.query.filter_by(tag="Closed").count() or 0
            },
            "messages": {
                "total": Message.query.count(),
                "recent": Message.query.filter(Message.timestamp >= one_hour_ago).count()
            },
            "users": {
                "total": WebUser.query.count() or 0,
                "roles": {str(r): count for r, count in user_roles_raw}
            },
            "tokens": AuthToken.query.count() if 'AuthToken' in globals() else 0,
            "tokensAgent": AuthTokenAgent.query.count() if 'AuthTokenAgent' in globals() else 0
        }
        logger.info(f"/dashboard_summary - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify(stats)
    except Exception as e:
        logger.error(f"/dashboard_summary Error: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
def list_users():
    try:
        logger.info(f"/list_users - Successful connection from {current_user.id} at {request.remote_addr}")
        users = WebUser.query.all()
        user_dict = {user.username: serialize_model(user) for user in users}
        return jsonify(user_dict)
    except Exception as e:
        logger.error(f"/list_users - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve user list"}), 500
def list_users_simple():
    try:
        logger.info(f"/list_users_simple - Successful connection from {current_user.id} at {request.remote_addr}")
        users = WebUser.query.all()
        user_roles = {user.username: user.role for user in users}
        return jsonify(user_roles)
    except Exception as e:
        logger.error(f"/list_users_simple - Database error: {e}")
        return jsonify({"error": "Failed to retrieve simple user list"}), 500
def list_tokens():
    try:
        logger.info(f"/list_tokens - Successful connection from {current_user.id} at {request.remote_addr}")
        tokens = AuthToken.query.all()
        token_dict = {token.token: serialize_model(token) for token in tokens}
        return jsonify(token_dict)
    except Exception as e:
        logger.error(f"/list_tokens - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve token list"}), 500
def list_tokens_number():
    try:
        logger.info(f"/list_tokens_number - Successful connection from {current_user.id} at {request.remote_addr}")
        token_count = AuthToken.query.count()
        return jsonify({"number": token_count})
    except Exception as e:
        logger.error(f"/list_tokens_number - Database error: {e}")
        return jsonify({"error": "Failed to retrieve token count"}), 500
def list_tokens_agent():
    try:
        logger.info(f"/list_tokens_agent - Successful connection from {current_user.id} at {request.remote_addr}")
        tokens = AuthTokenAgent.query.all()
        token_dict = {token.token: serialize_model(token) for token in tokens}
        return jsonify(token_dict)
    except Exception as e:
        logger.error(f"/list_tokens_agent - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve token list"}), 500
def list_tokens_agent_number():
    try:
        logger.info(f"/list_tokens_agent_number - Successful connection from {current_user.id} at {request.remote_addr}")
        token_count = AuthTokenAgent.query.count()
        return jsonify({"number": token_count})
    except Exception as e:
        logger.error(f"/list_tokens_agent_number - Database error: {e}")
        return jsonify({"error": "Failed to retrieve token count"}), 500
def list_agents():
    try:
        logger.info(f"/list_agents - Successful connection from {current_user.id} at {request.remote_addr}")
        agents = Agent.query.filter(Agent.agent_id != 'custom').all()
        agent_dict = {
            agent.agent_id: serialize_model(agent)
            for agent in agents
        }
        return jsonify(agent_dict)
    except Exception as e:
        logger.error(f"/list_agents - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve agent list"}), 500
def list_messages():
    try:
        results = (
            db.session.query(Message, Agent)
            .join(Agent, Agent.agent_id == Message.agent_id)
            .all()
        )
        message_dict = {}
        for message, agent in results:
            msg_data = serialize_model(message)
            msg_data.update({
                "agent_name": agent.agent_name,
                "agent_type": agent.agent_type,
                "hostname": agent.hostname,
                "ip": agent.ip,
            })
            message_dict[message.message_id] = msg_data
        logger.info(
            f"/list_messages - Successful connection from {current_user.id} at {request.remote_addr}"
        )
        return jsonify(message_dict)
    except Exception as e:
        logger.error(f"/list_messages - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve message list"}), 500
def list_incidents():
    try:
        logger.info(f"/list_incidents - Successful connection from {current_user.id} at {request.remote_addr}")
        incidents = Incident.query.all()
        incident_dict = {
            incident.incident_id: serialize_model(incident)
            for incident in incidents
        }
        return jsonify(incident_dict)
    except Exception as e:
        logger.error(f"/list_incidents - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve incident list"}), 500
def list_ansiblevars():
    try:
        logger.info(f"/list_ansiblevars - Successful connection from {current_user.id} at {request.remote_addr}")
        vars = AnsibleVars.query.filter_by(id="main").first() 
        if not vars:
            return jsonify({"status":"no ansiblevars database instance available"}), 200
        return jsonify(vars.to_dict()), 200
    except Exception as e:
        logger.error(f"/list_ansiblevars - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve ansiblevars list"}), 500
def set_ansiblevars():
    try:
        logger.info(f"/set_ansiblevars - Successful connection from {current_user.id} at {request.remote_addr}")
        vars = AnsibleVars.query.filter_by(id="main").first() 
        if not vars:
            return jsonify({"status":"no ansiblevars database instance available"}), 200
        return jsonify(vars.to_dict()), 200
    except Exception as e:
        logger.error(f"/set_ansiblevars - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve ansiblevars list"}), 500
def list_logfile(filepath=LOGFILE,lines=50):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            last_lines = deque(f, maxlen=lines)
        logger.info(f"/list_logfile - Successful connection from {current_user.id} at {request.remote_addr}")
        return list(last_lines)
    except FileNotFoundError:
        logger.error(f"/list_logfile - Successful connection from {current_user.id} at {request.remote_addr}")
        return f"FileNotFound {filepath}", 400
def list_ansibleresult():
    try:
        data = request.json
        taskID = data.get("taskID")
        if not all([taskID]): 
            logger.warning(f"/list_ansibleresult - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[taskID]}")
            return "Missing data", 400
        taskResult_obj = AnsibleResult.query.filter_by(task=taskID).one_or_none() 
        if taskResult_obj is None:
            logger.info(f"/list_ansibleresult - Failed connection from {current_user.id} at {request.remote_addr} - taskID is not available (not found/is pending). Full details: {[taskID]}")
            return jsonify({"status": "pending", "message": "Task not complete or ID invalid"}), 404
        task_data = taskResult_obj.to_dict() 
        logger.info(f"/list_ansibleresult - Successful connection from {current_user.id} at {request.remote_addr} for taskID {taskID}")
        return jsonify(task_data), 200
    except Exception as e:
        logger.error(f"/list_ansibleresult - Database or serialization error: {e}")
        return jsonify({"error": "Failed to retrieve result details"}), 
def agent_pause():
    data = request.json
    agent_id = data.get("agent_id")
    seconds = data.get("seconds")
    if not all([agent_id,seconds]):
        logger.warning(f"/agent_pause - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[agent_id,seconds]}")
        return "Missing data", 400
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    if not agent:
        logger.warning(f"/agent_pause - Failed connection from {current_user.id} at {request.remote_addr} - bad agent_id value, agent_id does not exist. Full details: {[agent_id,seconds]}")
        return "Agent with specified ID does not exist", 400
    try:
        agent.pausedUntil = str(time.time() + seconds)
        db.session.commit()
        logger.info(f"/agent_pause - Successful connection from {current_user.id} at {request.remote_addr}. Pausing agent {agent_id} for {seconds} seconds.")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/agent_pause - Database error: {e}")
        return jsonify({"error": f"Database error: {e}"}), 500
def agent_resume():
    data = request.json
    agent_id = data.get("agent_id")
    logger.info(f"/agent_resume - {data}")
    if not all([agent_id]):
        logger.warning(f"/agent_resume - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[agent_id]}")
        return "Missing data", 400
    agent = Agent.query.filter_by(agent_id=agent_id).first()
    if not agent:
        logger.warning(f"/agent_resume - Failed connection from {current_user.id} at {request.remote_addr} - bad agent_id value, agent_id does not exist. Full details: {[agent_id]}")
        return f"Agent with specified ID {agent_id} does not exist", 400
    try:
        logger.info(f"/agent_resume - 1")
        pausedUntilInt = int(agent.pausedUntil)
        logger.info(f"/agent_resume - ")
        if (pausedUntilInt == 0) or (pausedUntilInt == 1):
            return "Agent is already in ACTIVE state", 400
        logger.info(f"/agent_resume - 3")
        agent.pausedUntil = "1"
        logger.info(f"/agent_resume - 4")
        db.session.commit()
        logger.info(f"/agent_resume - 5")
        logger.info(f"/agent_resume - Successful connection from {current_user.id} at {request.remote_addr}. Resuming agent {agent_id}.")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/agent_resume - Database error: {e}")
        return jsonify({"error": f"Database error: {e}"}), 500
def add_incident():
    data = request.json
    newStatus = data.get("newStatus")
    message = data.get("message")
    assignee = data.get("assignee","")
    createAlert = data.get("createAlert")
    sla = data.get("sla",0)
    if not sla:
        sla = 0
    if not all([message]): 
        logger.warning(f"/add_incident - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[newStatus,message,assignee,createAlert,sla]}")
        return "Missing data", 400
    try:
        sla = float(sla)
    except:
        logger.warning(f"/add_incident - Failed connection from {current_user.id} at {request.remote_addr} - bad sla value. Full details: {[newStatus,message,assignee,createAlert,sla]}")
        return "Bad SLA value", 400
    messageDict = {
        "timestamp": time.time(),
        "agent_id": "custom",
        "oldStatus": True,
        "newStatus": newStatus,
        "message": message,
        "sla": sla
    }
    create_incident(messageDict,tag="New",assignee=assignee,createAlert=createAlert)
    logger.info(f"/add_incident - Successful connection from {current_user.id} at {request.remote_addr}. Creating incident with details {[newStatus,message,assignee,createAlert,sla]}.")
    return jsonify({"status": "ok"})
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
def delete_token_agent():
    data = request.json
    token = data.get("token")
    if not all([token]):
        logger.warning(f"/delete_token_agent - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[token]}")
        return "Missing data", 400
    token_to_delete = AuthTokenAgent.query.filter_by(token=token).first()
    if not token_to_delete:
        logger.warning(f"/delete_token_agent - Failed connection from {current_user.id} at {request.remote_addr} - username not found. Full details: {[token]}")
        return "Bad role value", 400
    try:
        added_by = token_to_delete.added_by
        timestamp = datetime.fromtimestamp(token_to_delete.timestamp)
        incident_data = {
            "timestamp": time.time(),
            "agent_id": "custom",
            "oldStatus": False,
            "newStatus": False,
            "message": f"Server - Agent Token Deleted by User {current_user.id}",
            "sla": 0
        }
        create_incident(incident_data)
        db.session.delete(token_to_delete)
        db.session.commit()
        logger.info(f"/delete_token_agent - Successful connection from {current_user.id} at {request.remote_addr}. Deleting token {token} that was added by {added_by} at {timestamp}")
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"/delete_token_agent - Database error: {e}")
        return jsonify({"error": "Database error while deleting token"}), 500
def update_incident_tag():
    data = request.json
    incident_id = data.get("incident_id")
    tag = data.get("tag")
    if not all([incident_id, tag]):
        logger.warning(f"/update_incident_tag - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, tag]}")
        return "Missing data", 400
    try:
        incident_id = int(incident_id)
    except:
        logger.warning(f"/update_incident_tag - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, tag]}")
        return "Bad incident value", 400
    if tag not in ["New","Active","Closed"]:
        logger.info(f"/update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. Invalid tag {tag}")
        return "Bad tag value", 400
    incident = db.session.get(Incident,incident_id)
    if incident:
        try:
            incident.tag = tag
            db.session.commit()
            logger.info(f"update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. Updating tag for incident {incident_id} to {tag}")
            return jsonify({"status": "ok"}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"/update_incident_tag - Database update error: {e}")
            return jsonify({"error": "Database error during update"}), 500
    else:
        logger.warning(f"/update_incident_tag - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}")
        return "Invalid incident ID", 400
def update_incident_assignee():
    data = request.json
    incident_id = data.get("incident_id")
    assignee = data.get("assignee")
    if not all([incident_id, assignee]):
        logger.warning(f"/update_incident_assignee - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, assignee]}")
        return "Missing data", 400
    try:
        incident_id = int(incident_id)
    except:
        logger.warning(f"/update_incident_assignee - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, assignee]}")
        return "Bad incident value", 400
    incident = db.session.get(Incident,incident_id)
    if incident:
        try:
            incident.assignee = assignee
            db.session.commit()
            logger.info(f"/update_incident_assignee - Successful connection from {current_user.id} at {request.remote_addr}. Updating assignee for incident {incident_id} to {assignee}")
            return jsonify({"status": "ok"}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"/update_incident_assignee - Database update error: {e}")
            return jsonify({"error": "Database error during update"}), 500
    else:
        logger.warning(f"/update_incident_assignee - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}")
        return "Invalid incident ID", 400
def update_incident_sla():
    data = request.json
    incident_id = data.get("incident_id")
    sla = data.get("sla")
    if not all([incident_id, sla]):
        logger.warning(f"/update_incident_sla - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[incident_id, sla]}")
        return "Missing data", 400
    try:
        incident_id = int(incident_id)
    except:
        logger.warning(f"/update_incident_sla - Failed connection from {current_user.id} at {request.remote_addr} - Invalid incident ID {incident_id} (failed to parse to int). Full details: {[incident_id, sla]}")
        return "Bad incident value", 400
    try:
        sla = int(sla)
    except Exception as E:
        logger.warning(f"/update_incident_sla - Successful connection from {current_user.id} at {request.remote_addr}. Cannot cast SLA of {sla} to int.")
        return "Bad sla value", 400
    incident = db.session.get(Incident,incident_id)
    if incident:
        try:
            incident.sla = sla
            db.session.commit()
            logger.info(f"/update_incident_sla - Successful connection from {current_user.id} at {request.remote_addr}. Updating sla for incident {incident_id} to {sla}")
            return jsonify({"status": "ok"}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"/update_incident_sla - Database update error: {e}")
            return jsonify({"error": "Database error during update"}), 500
    else:
        logger.warning(f"/update_incident_sla - Successful connection from {current_user.id} at {request.remote_addr}. No incident found with id {incident_id}")
        return "Invalid incident ID", 400
def add_ansible():
    data = request.json
    ansible_folder = data.get("ansible_folder")
    ansible_playbook = data.get("ansible_playbook")
    ansible_inventory = data.get("ansible_inventory")
    dest_ip = data.get("dest_ip")
    ansible_venv = data.get("ansible_venv","")
    extra_vars = data.get("extra_vars")
    if not all([ansible_folder,ansible_playbook,ansible_inventory,dest_ip,extra_vars]):
        logger.warning(f"/add_ansible - Failed connection from {current_user.id} at {request.remote_addr} - missing data. Full details: {[ansible_folder,ansible_playbook,ansible_inventory,dest_ip,extra_vars]}")
        return jsonify({"status":"Missing data"}), 400
    new_task = AnsibleQueue(
        ansible_folder=ansible_folder,
        ansible_playbook=ansible_playbook,
        ansible_inventory=ansible_inventory,
        dest_ip=dest_ip,
        ansible_venv=ansible_venv,
        extra_vars=extra_vars
    )
    db.session.add(new_task)
    db.session.commit()
    taskID = new_task.id
    logger.info(f"/add_ansible - Successful connection from {current_user.id} at {request.remote_addr} - Task {taskID} queued via DB for IP {dest_ip}")
    return jsonify({"status": "ok", "task": taskID}), 200
def get_task():
    try:
        data = request.get_json(silent=True) or {}
        task_id = data.get('id')
        agent_id = data.get('agent_id')
        query = AgentTask.query
        if task_id:
            task = query.get(task_id)
            if not task:
                logger.warning(f"/get_task - Failed connection from {current_user.id} at {request.remote_addr} - task not found for id {task_id}")
                return jsonify({"error": "Task not found"}), 404
            logger.info(f"/get_task - Successful connection from {current_user.id} at {request.remote_addr} - returning task {task_id}")
            return jsonify(task.to_dict()), 200
        if agent_id:
            tasks = query.filter_by(agent_id=agent_id).order_by(AgentTask.created_at.desc()).all()
        else:
            tasks = query.order_by(AgentTask.created_at.desc()).all()
        returned_tasks = [t.to_dict() for t in tasks]
        logger.info(f"/get_task - Successful connection from {current_user.id} at {request.remote_addr} - returning all tasks for agent {agent_id} ({len(returned_tasks)} tasks)")
        return jsonify(returned_tasks), 200
    except Exception as e:
        logger.error(f"/get_task - Failed connection from {current_user.id} at {request.remote_addr} - internal error when fetching (task {task_id}) or (agent_id {agent_id}): {e}")
        return jsonify({"error": "Internal server error"}), 500
def get_tasks_all():
    try:
        agents = Agent.query.options(joinedload(Agent.agent_tasks)).all()
        results = []
        for agent in agents:
            if agent.agent_id == 'custom':
                continue
            sorted_tasks = sorted(
                agent.agent_tasks, 
                key=lambda x: x.created_at, 
                reverse=True
            )
            agent_data = {
                "agent_id": agent.agent_id,
                "hostname": agent.hostname,
                "ip": agent.ip,
                "os": agent.os,
                "lastSeenTime": agent.lastSeenTime,
                "task_count": len(sorted_tasks),
                "tasks": [t.to_dict() for t in sorted_tasks]
            }
            results.append(agent_data)
        logger.info(
            f"/get_tasks_all - Successful connection from {current_user.id} at "
            f"{request.remote_addr} - Returning {len(results)} agents with nested task history"
        )
        return jsonify(results), 200
    except Exception as e:
        logger.error(
            f"/get_tasks_all - Failed connection from {current_user.id} at "
            f"{request.remote_addr} - internal error: {e}"
        )
        return jsonify({"error": "Internal server error"}), 500
def add_task():
    try:
        data = request.get_json()
        agent_id = data.get('agent_id')
        task_command = data.get('task')
        if not agent_id or not task_command:
            logger.warning(f"/get_task - Failed connection from {current_user.id} at {request.remote_addr} - missing agent_id ({agent_id}) and/or task ({task_command}) fields")
            return jsonify({"error": "agent_id and task are required fields"}), 400
        agent = Agent.query.get(agent_id)
        if not agent:
            logger.warning(f"/get_task - Failed connection from {current_user.id} at {request.remote_addr} - target agent_id {agent_id} does not exist")
            return jsonify({"error": "Target agent does not exist"}), 404
        new_task = AgentTask(
            agent_id=agent_id,
            task=task_command,
            result="PENDING"
        )
        db.session.add(new_task)
        db.session.commit()
        logger.info(f"/get_task - Successful connection from {current_user.id} at {request.remote_addr} - created task {new_task.id}")
        return jsonify({
            "message": "Task queued successfully",
            "task_id": new_task.id,
            "local_index": new_task.local_index
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"/get_task - Failed connection from {current_user.id} at {request.remote_addr} - internal error when adding task for agent_id {agent_id} with task {task_command}: {e}")
        return jsonify({"error": "Failed to queue task"}), 500
def add_task_bulk():
    try:
        data = request.get_json()
        task_command = data.get('task')
        if not task_command:
            return jsonify({"error": "Task command is required"}), 400
        agents = Agent.query.all()
        if not agents:
            return jsonify({"error": "No agents found"}), 404
        new_tasks = []
        for agent in agents:
            t = AgentTask(
                agent_id=agent.agent_id,
                task=task_command,
                result="PENDING"
            )
            new_tasks.append(t)
        db.session.add_all(new_tasks)
        db.session.commit()
        logger.info(f"/add_task_bulk - {current_user.id} queued '{task_command}' for {len(new_tasks)} agents")
        return jsonify({
            "message": f"Task queued for {len(new_tasks)} agents",
            "count": len(new_tasks)
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"/add_task_bulk - Error: {e}")
        return jsonify({"error": "Internal server error"}), 500