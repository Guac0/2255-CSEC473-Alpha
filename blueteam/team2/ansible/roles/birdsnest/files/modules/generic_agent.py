from flask import request, jsonify
import time
import os
import json
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
def beacon_generic_handler():
    returnMsg, returnCode, registered, agent_id, current_time = beacon_generic("/agent/beacon")
    if returnCode != 200:
        return returnMsg, returnCode
    data = request.json
    oldStatus = data.get("oldStatus",True), 
    newStatus = data.get("newStatus",True), 
    message = data.get("message","") 
    if message:
        try:
            message_id = hash_id(current_time, agent_id)
            new_message = Message(
                message_id = message_id,
                timestamp=current_time,
                agent_id=agent_id,
                oldStatus=oldStatus,
                newStatus=newStatus,
                message=message
            )
            db.session.add(new_message)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"/agent/beacon - Failed to create message for agent {agent_id}: {e}")
            pass
    logger.info(f"/agent/beacon - Successful connection from {request.remote_addr}. Full details: {request.json}") 
    return returnMsg, 200
def beacon_generic(endpoint):
    data = request.json
    request_info = {
        "agent_name": data.get("name",""), 
        "agent_type": data.get("agent_type",""), 
        "hostname": data.get("hostname",""), 
        "ip": data.get("ip",""), 
        "os_name": data.get("os",""), 
        "executionUser": data.get("executionUser",""), 
        "executionAdmin": data.get("executionAdmin",False), 
        "auth": data.get("auth",""), 
        "oldStatus": data.get("oldStatus",True), 
        "newStatus": data.get("newStatus",True), 
        "message": data.get("message","") 
    }
    current_time = time.time()
    if not all([
        request_info["agent_name"],
        request_info["agent_type"],
        request_info["hostname"],
        request_info["ip"],
        request_info["os_name"],
        request_info["auth"]
    ]): 
        logger.warning(f"{endpoint} - Failed connection from {request.remote_addr} - missing data. Full details: {request_info}")
        return "missing data", 400, False, "", current_time
    agent_id = hash_id(request_info["agent_name"], request_info["hostname"], request_info["ip"], request_info["os_name"])
    auth_token_agent_record = AuthTokenAgent.query.filter_by(agent_id=agent_id).first()
    if not auth_token_agent_record:
        auth_token_record = AuthToken.query.filter_by(token=request_info["auth"]).first()
        if not auth_token_record:
            logger.warning(f"{endpoint} - Failed connection from {request.remote_addr} - invalid auth token. Full details: {request_info}")
            return "unauthorized - no/bad auth", 403, False, "", current_time
    try:
        agent = db.session.get(Agent,agent_id)
        is_reregister_request = request_info["message"].split(" ")[0].lower() == "reregister"
    except Exception:
        is_reregister_request = False
    try:
        if is_reregister_request and agent:
            db.session.delete(agent)
            if auth_token_agent_record:
                db.session.delete(auth_token_agent_record)
            agent = None 
            logger.info(f"{endpoint} - Reregistering and deleting old agent record for agent {agent_id} with details: {request_info}")
        if not agent:
            new_agent = Agent(
                agent_id=agent_id,
                agent_name=request_info["agent_name"],
                agent_type=request_info["agent_type"],
                hostname=request_info["hostname"],
                ip=request_info["ip"],
                os=request_info["os_name"],
                executionUser=request_info["executionUser"],
                executionAdmin=request_info["executionAdmin"],
                lastSeenTime=current_time,
                lastStatus=request_info["newStatus"],
                pausedUntil=str(0)
            )
            db.session.add(new_agent)
        else:
            agent.lastSeenTime = current_time
            agent.lastStatus = request_info["newStatus"]
        if not auth_token_agent_record:
            new_token_value = os.urandom(6).hex()
            new_token = AuthTokenAgent(
                token=new_token_value,
                added_by="registration",
                agent_id=agent_id
            )
            db.session.add(new_token)
            db.session.commit()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"{endpoint} - Failed to register or update agent {agent_id}: {e}")
        return "database error during agent update or registration", 500, not agent, agent_id, current_time
    return f"{AuthTokenAgent.query.filter_by(agent_id=agent_id).first().token}", 200, not agent, agent_id, current_time
    try:
        message_id = hash_id(current_time, agent_id)
        new_message = Message(
            message_id = message_id,
            timestamp=current_time,
            agent_id=agent_id,
            oldStatus=request_info["oldStatus"],
            newStatus=request_info["newStatus"],
            message=request_info["message"]
        )
        db.session.add(new_message)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"{endpoint} - Failed to create message for agent {agent_id}: {e}")
        pass
    """
    # 5. Handle RESUME Logic (DB Read/Write)
    try:
        # Check for RESUME message pattern
        if message.lower().split(" - ")[1].split(" ")[0] == "resumed":
            # 5a. Update Agent Status
            # We already have the agent record (or the new one was created)
            current_agent = db.session.get(Agent,agent_id)
            if current_agent:
                current_agent.pausedUntil = 0
                db.session.commit()
            # 5b. Find and Close Incident
            pattern = r'(\\d+)\\s*seconds\\b' # remove extra slashes if this is uncommented
            match = re.search(pattern, message)
            if match:
                seconds = int(match.group(1))
                # Search for the corresponding PAUSE incident that is still open
                incident_to_close = Incident.query.filter(
                    Incident.agent_id == agent_id,
                    Incident.tag.in_(["New", "Active"]),
                    # Match either the full message or the 'EARLY EXIT' message
                    or_(
                        Incident.message.like(f"%Resumed after sleeping for {seconds} seconds%"),
                        Incident.message.like(f"%Resumed after sleeping for {seconds} seconds, EARLY EXIT%")
                    )
                ).first()
                if incident_to_close:
                    incident_to_close.tag = "Closed"
                    db.session.commit()
                else:
                    logger.warning(f"/beacon - RESUME message received but no open incident found to close for agent {agent_id}.")
            else:
                logger.error(f"/beacon - cannot parse seconds attribute in resume incident. Full message: {message}.")
    except Exception as e:
        # Catches exceptions from message parsing or DB operations within the RESUME block
        db.session.rollback() 
        logger.error(f"/beacon - Error processing RESUME logic for agent {agent_id}: {e}")
    """
def get_pause():
    try:
        data = request.json
        agent_name = data.get("name","")
        agent_type = data.get("agent_type","")
        hostname = data.get("hostname","")
        ip = data.get("ip","")
        os_name = data.get("os","")
        executionUser = data.get("executionUser","")
        executionAdmin = data.get("executionAdmin","")
        auth = data.get("auth","")
        if not all([agent_name, agent_type, hostname, ip, os_name, auth]): 
            logger.warning(f"/agent/get_pause - Failed connection from {request.remote_addr} - missing data. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
            return "Missing data", 400
        agent_id = hash_id(agent_name, hostname, ip, os_name)
        auth_token_record = AuthTokenAgent.query.filter_by(agent_id=agent_id).first()
        if not auth_token_record:
            logger.warning(f"/agent/get_pause - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
            return "unauthorized - no/bad auth", 403
        agent = db.session.get(Agent,agent_id)
        if not agent:
            logger.warning(f"/agent/get_pause - Failed connection from {request.remote_addr} - no agent. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
            return "unauthorized - no agent", 403
        return str(float(agent.pausedUntil)), 200
    except Exception as E:
        logger.error(f"/agent/get_pause - Failed connection from {request.remote_addr} - internal error: {E}")
        return "", 500
def get_task_agent():
    try:
        data = request.json
        agent_name = data.get("name","")
        agent_type = data.get("agent_type","")
        hostname = data.get("hostname","")
        ip = data.get("ip","")
        os_name = data.get("os","")
        executionUser = data.get("executionUser","")
        executionAdmin = data.get("executionAdmin","")
        auth = data.get("auth","")
        if not all([agent_name, agent_type, hostname, ip, os_name, auth]): 
            logger.warning(f"/agent/get_task - Failed connection from {request.remote_addr} - missing data. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
            return "Missing data", 400
        agent_id = hash_id(agent_name, hostname, ip, os_name)
        auth_token_record = AuthTokenAgent.query.filter_by(agent_id=agent_id).first()
        if not auth_token_record:
            logger.warning(f"/agent/get_task - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
            return "unauthorized - no/bad auth", 403
        agent_id = hash_id(agent_name, hostname, ip, os_name)
        agent = db.session.get(Agent,agent_id)
        if not agent:
            logger.warning(f"/agent/get_task - Failed connection from {request.remote_addr} - no agent. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
            return "unauthorized - no agent", 403
        task_entry = AgentTask.query.filter_by(agent_id=agent_id, result="PENDING")                                    .order_by(AgentTask.created_at.asc())                                    .first()
        if task_entry:
            try:
                task_entry.result="SENT"
                db.session.commit()
                logger.info(f"/agent/get_task - Successful connection from {request.remote_addr} - returning task {task_entry.id}")
                return jsonify({
                    "task_id": task_entry.id,
                    "task": task_entry.task,
                    "local_index": task_entry.local_index
                }), 200
            except Exception as E:
                db.session.rollback()
                logger.error(f"/agent/get_task - Failed connection from {request.remote_addr} - internal error when setting task to SENT status for agent {agent_id}: {E}")
                return "", 500
        logger.info(f"/agent/get_task - Successful connection from {request.remote_addr} - no tasks waiting for agent {agent_id}")
        return "no pending tasks", 200
    except Exception as E:
        logger.error(f"/agent/get_task - Failed connection from {request.remote_addr} - internal error: {E}")
        return "", 500
def set_task_result():
    data = request.json
    agent_name = data.get("name","")
    agent_type = data.get("agent_type","")
    hostname = data.get("hostname","")
    ip = data.get("ip","")
    os_name = data.get("os","")
    executionUser = data.get("executionUser","")
    executionAdmin = data.get("executionAdmin","")
    auth = data.get("auth","")
    message = data.get("message","")
    if not all([agent_name, agent_type, hostname, ip, os_name, auth]): 
        logger.warning(f"/set_task_result - Failed connection from {request.remote_addr} - missing data. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth]}")
        return "Missing data", 400
    agent_id = hash_id(agent_name, hostname, ip, os_name)
    auth_token_record = AuthTokenAgent.query.filter_by(agent_id=agent_id).first()
    if not auth_token_record:
        logger.warning(f"/set_task_result - Failed connection from {request.remote_addr} - invalid auth token. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth, message]}")
        return "unauthorized - no/bad auth", 403
    agent_id = hash_id(agent_name, hostname, ip, os_name)
    agent = db.session.get(Agent,agent_id)
    if not agent:
        logger.warning(f"/set_task_result - Failed connection from {request.remote_addr} - no agent. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth, message]}")
        return "unauthorized - no agent", 403
    try:
        data2 = json.loads(message)
    except Exception as E:
        logger.warning(f"/set_task_result - Failed connection from {request.remote_addr} - message failed when using json.loads ({E}). Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth, message, task_id, result_text]}")
        return "bad message value", 400
    task_id = data2.get('task_id')
    result_text = data2.get('result')
    if task_id is None or result_text is None:
        logger.warning(f"/set_task_result - Failed connection from {request.remote_addr} - missing task_id or result. Full details: {[agent_name, agent_type, hostname, ip, os_name, executionUser, executionAdmin, auth, message, task_id, result_text]}")
        return "Missing task_id or result", 400
    task_entry = AgentTask.query.get(task_id)
    if not task_entry:
        logger.warning(f"/set_task_result - Failed connection from {request.remote_addr} - no task found for id {task_id}")
        return "Task not found", 400
    try:
        task_entry.result = result_text
        db.session.commit()
        logger.info(f"/set_task_result - Successful connection from {request.remote_addr} - result for task {task_id} recorded: {result_text}")
        return "success", 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"/set_task_result - Failed connection from {request.remote_addr} - internal error when setting result for task {task_id}: {e}")
        return "Database update failed", 500