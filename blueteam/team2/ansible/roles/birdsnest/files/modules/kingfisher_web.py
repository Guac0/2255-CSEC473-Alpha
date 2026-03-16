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
def list_system_users():
    try:
        data = request.get_json(silent=True) or {}
        agent_id = data.get('agent_id')
        query = SystemUser.query
        if agent_id:
            users = query.filter_by(agent_id=agent_id).order_by(SystemUser.username.asc()).all()
            log_msg = f"returning users for agent {agent_id}"
        else:
            users = query.order_by(SystemUser.agent_id.asc(), SystemUser.username.asc()).all()
            log_msg = "returning all system users"
        returned_users = [u.to_dict() for u in users]
        logger.info(f"/list_system_users - Successful connection from {current_user.id} at {request.remote_addr} - {log_msg} ({len(returned_users)} users)")
        return jsonify(returned_users), 200
    except Exception as e:
        logger.error(f"/list_system_users - Failed connection from {current_user.id} at {request.remote_addr} - internal error when fetching for agent_id {agent_id}: {e}")
        return jsonify({"error": "Internal server error"}), 500
def list_system_users_all():
    try:
        agents = Agent.query.options(joinedload(Agent.system_users)).all()
        results = []
        for agent in agents:
            agent_data = {
                "agent_id": agent.agent_id,
                "agent_name": agent.agent_name,
                "hostname": agent.hostname,
                "ip": agent.ip,
                "os": agent.os,
                "lastStatus": agent.lastStatus,
                "stale": agent.stale,
                "users": [u.to_dict() for u in agent.system_users]
            }
            results.append(agent_data)
        logger.info(
            f"/list_system_users_all - Successful connection from {current_user.id} at "
            f"{request.remote_addr} - Returning {len(results)} agents with nested user data"
        )
        return jsonify(results), 200
    except Exception as e:
        logger.error(
            f"/list_system_users_all - Failed connection from {current_user.id} at "
            f"{request.remote_addr} - internal error: {e}"
        )
        return jsonify({"error": "Internal server error"}), 500