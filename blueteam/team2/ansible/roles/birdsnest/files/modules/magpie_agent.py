from flask import request, jsonify
import subprocess
import os
import shutil
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
def beacon_magpie():
    returnMsg, returnCode, registered, agent_id, current_time = beacon_generic("/agent/beacon/magpie")
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
            message=message
        )
        db.session.add(new_message)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"/beacon_magpie - Failed to create message for agent {agent_id}: {e}")
    if oldStatus == False:
        incident_data = {
            "timestamp": current_time,
            "agent_id": agent_id,
            "oldStatus": oldStatus,
            "newStatus": newStatus,
            "message": message,
            "sla": 0
        }
        create_incident(incident_data)
    if registered:
        repo_path = os.path.join(GIT_PROJECT_ROOT,f"{agent_id}.git")
        if len(repo_path) < 60:
            logger.error(f"/agent/beacon/magpie - calculated repo_path is unusually short (parsing error?). agent_id: {agent_id}, repo_path: {repo_path}")
            return "bad calculation for repo_path", 500
        if os.path.exists(repo_path):
            if os.path.isdir(repo_path):
                shutil.rmtree(repo_path)
                logger.info(f"/beacon_magpie: removed existing repo at {repo_path} as part of re-registration logic")
            else:
                os.remove(repo_path)
                logger.warning(f"/beacon_magpie: removed existing repo at {repo_path} as part of re-registration logic - but it was a file instead of a folder?")
        try:
            run_git(["init", "--bare", f"{agent_id}.git"],GIT_PROJECT_ROOT)
            run_git(["config", "-f", f"{agent_id}.git/config", "http.receivepack", "true"],GIT_PROJECT_ROOT)
            logger.info(f"/beacon_magpie: created repo {os.path.join(GIT_PROJECT_ROOT,f'{agent_id}.git')}")
        except Exception as e:
            logger.error(f"/beacon_magpie: Error occurred when creating git repo {repo_path} - {e.stderr}")
            return returnMsg, 500
    return returnMsg, 200
def git_backend(repo_name, git_path):
    content_length = request.headers.get('Content-Length', '0')
    logger.info(f"/git: Incoming push size: {content_length} bytes from {request.remote_addr}")
    try:
        try:
            git_path = clean_and_join_path(git_path)
        except Exception as e:
            logger.error(f"/git: CRASH in clean_and_join_path: {str(e)}")
            return f"Path cleaning failed: {str(e)}", 500
        env = {
            'REQUEST_METHOD': request.method,
            'GIT_PROJECT_ROOT': GIT_PROJECT_ROOT,
            'GIT_HTTP_EXPORT_ALL': '1',
            'PATH_INFO': f"/{repo_name}.git/{git_path}" if git_path else f"/{repo_name}.git/",
            'QUERY_STRING': request.query_string.decode('utf-8') if request.query_string else '',
            'CONTENT_TYPE': request.headers.get('Content-Type', ''),
            'CONTENT_LENGTH': request.headers.get('Content-Length', ''),
            'REMOTE_ADDR': request.remote_addr,
            'REMOTE_USER': 'git_user',
        }
        if not os.path.exists(GIT_BACKEND):
            logger.critical(f"/git: CRITICAL: GIT_BACKEND binary not found at {GIT_BACKEND}")
            return "Backend binary missing", 500
        process = subprocess.Popen(
            [GIT_BACKEND],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(input=request.data)
        if process.returncode != 0:
            logger.warning(f"/git: Git binary returned {process.returncode}. Stderr: {stderr.decode('utf-8')}")
        header_end = stdout.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = stdout.find(b'\n\n')
            sep_len = 2
        else:
            sep_len = 4
        if header_end == -1:
            logger.warning(f"/git: CGI ERROR: No header separator. Raw Output: {stdout[:200]}")
            return "Invalid response from Git backend", 500
        header_section = stdout[:header_end].decode('utf-8')
        response_body = stdout[header_end + sep_len:]
        header_end = stdout.find(b'\r\n\r\n')
        sep_len = 4
        if header_end == -1:
            header_end = stdout.find(b'\n\n')
            sep_len = 2
        if header_end == -1:
            logger.warning(f"/git: CGI Header Parse Error: No header separator found in binary output. Raw output start: {stdout[:50]}")
            return "Internal Server Error: Invalid CGI Response", 500
        header_section = stdout[:header_end].decode('utf-8')
        response_body = stdout[header_end + sep_len:]
        headers_dict = {}
        status_code = 200
        for line in header_section.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                k = key.strip().lower()
                v = value.strip()
                if k == 'status':
                    try:
                        status_code = int(v.split(' ')[0])
                    except ValueError:
                        logger.warning(f"/git: Malformed Status header: {v}")
                else:
                    headers_dict[key.strip()] = v
        logger.info(f"/git - Successful connection from {request.remote_addr}.")
        return response_body, status_code, headers_dict
    except FileNotFoundError:
        logger.error(f"/git: GIT_BACKEND binary not found at: {GIT_BACKEND}")
        return "Internal Server Error: Backend Binary Missing", 500
    except PermissionError:
        logger.error(f"/git: Permission denied when executing GIT_BACKEND: {GIT_BACKEND}")
        return "Internal Server Error: Backend Permission Denied", 500
    except Exception as e:
        logger.error(f"/git: Unexpected error in git_backend: {str(e)}")
        return "Internal Server Error", 500