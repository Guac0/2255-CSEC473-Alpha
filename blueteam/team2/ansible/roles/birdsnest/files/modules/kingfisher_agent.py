from flask import request, jsonify
import ast
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
from modules.generic_agent import beacon_generic
logger = setup_logging("web")
def beacon_kingfisher():
    returnMsg, returnCode, registered, agent_id, current_time = beacon_generic("/agent/beacon/kingfisher")
    if returnCode != 200:
        return returnMsg, returnCode
    data = request.json
    oldStatus = data.get("oldStatus",False) 
    newStatus = data.get("newStatus",False) 
    message = data.get("message","") 
    try:
        message_id = hash_id(current_time, agent_id)
        new_message = Message(
            message_id = message_id,
            timestamp=current_time,
            agent_id=agent_id,
            oldStatus=oldStatus,
            newStatus=newStatus,
            message=str(message) 
        )
        db.session.add(new_message)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"/beacon_kingfisher - Failed to create message for agent {agent_id}: {e}")
    try:
        try:
            users = ast.literal_eval(message)
        except:
            logger.info(f"/beacon_kingfisher - Successful connection from {request.remote_addr}. Message: {message}")
            return returnMsg, 200
        existing_users = {
            u.username: u for u in SystemUser.query.filter_by(agent_id=agent_id).all()
        }
        new_records = []
        updated_count = 0
        for user_data in users:
            username = user_data['username']
            if username in existing_users:
                db_user = existing_users[username]
                changed = False
                if db_user.admin != user_data['admin']:
                    db_user.admin = user_data['admin']
                    changed = True
                if db_user.locked != user_data['locked']:
                    db_user.locked = user_data['locked']
                    changed = True
                if db_user.last_login != user_data['last_login']:
                    db_user.last_login = user_data['last_login']
                    changed = True
                if changed:
                    updated_count += 1
            else:
                new_user = SystemUser(
                    agent_id=agent_id,
                    username=username, 
                    admin=user_data['admin'],
                    locked=user_data['locked'],
                    last_login=user_data['last_login'],
                    account_type=user_data['account_type']
                )
                new_records.append(new_user)
        if new_records:
            db.session.add_all(new_records)
        db.session.commit()
        logger.info(f"/beacon_kingfisher - Successful connection from {request.remote_addr}. Sync Complete for Agent {agent_id}: {len(new_records)} added, {updated_count} updated.")
        return returnMsg, 200
    except Exception as E:
        db.session.rollback()
        logger.error(f"/beacon_kingfisher - Failed to update users for agent {agent_id}: {E}")
        return "Failed to sync users due to internal error", 500