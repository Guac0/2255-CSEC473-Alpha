from flask_login import login_user, current_user, current_user
from flask import current_app, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import time
import os
from collections import deque
from urllib.parse import unquote_plus
from sqlalchemy import func
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
def get_repo_history():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    try:
        fmt = "%H|%at|%s|%D|%N"
        cmd = ["log", "--all", f"--pretty=format:{fmt}", "--name-status", "--topo-order"]
        result = run_git(cmd, cwd=repo_path)
        history = []
        blocks = result.stdout.split('')
        for block in blocks:
            if not block.strip(): continue
            lines = block.strip().split('\n')
            header = lines[0].split('|')
            if len(header) >= 4:
                h, t, s, d = header[0], header[1], header[2], header[3]
                n = header[4] if len(header) > 4 else ""
                branch = "good" if "good" in d else ("bad" if "bad" in d else "")
                commit_item = {
                    "hash": h, 
                    "time": datetime.fromtimestamp(int(t)).strftime('%Y-%m-%d %H:%M:%S'),
                    "name": s, "branch": branch, "notes": n.strip(), "changes": []
                }
                for line in lines[1:]:
                    p = line.split('\t')
                    if len(p) == 2:
                        commit_item["changes"].append({"type": p[0], "file": p[1]})
                history.append(commit_item)
        logger.info(f"/get_repo_history - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify(history), 200
    except Exception as e:
        logger.warning(f"/get_repo_history - Failed connection from {current_user.id} at {request.remote_addr}. Git error: {str(e)}")
        return jsonify({"error": str(e)}), 500
def get_commit_diff():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    cmd = ["diff", "good", data.get("hash")]
    try:
        result = run_git(cmd, cwd=repo_path)
        logger.info(f"/get_commit_diff - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify({"diff": result.stdout}), 200
    except Exception as E:
        logger.warning(f"/get_commit_diff - Failed connection from {current_user.id} at {request.remote_addr}. Git error: {str(E)}")
def list_git_overall():
    try:
        returned_info = get_git_stats(db)
        logger.info(f"/list_git_overall - Successful connection from {current_user.id} at {request.remote_addr}.")
        return jsonify(returned_info), 200
    except Exception as E:
        logger.warning(f"/list_git_overall - Failed connection from {current_user.id} at {request.remote_addr}. Exception: {E}")
        return "",500
def save_git_note():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    run_git(["config", "user.name", "Dashboard-Operator"], cwd=repo_path)
    run_git(["config", "user.email", f"operator@server.local"], cwd=repo_path)
    cmd = ["notes", "add", "-f", "-m", data.get("note"), data.get("hash")]
    result = run_git(cmd, cwd=repo_path)
    if result.returncode == 0:
        logger.info(f"/save_git_note - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify({"status": "success"}), 200
    logger.warning(f"/save_git_note - Failed connection from {current_user.id} at {request.remote_addr}. Failed to execute git: {result.stderr}")
    return jsonify({"error": result.stderr}), 500
def set_good_branch():
    data = request.json
    repo_path = os.path.join(current_app.root_path, 'repos', data.get("repo_name"))
    target_hash = data.get("hash")
    try:
        for branch in ["good","bad"]:
            run_git(["checkout", branch], cwd=repo_path)
            run_git(["checkout", target_hash, "--", "."], cwd=repo_path)
            run_git(["commit", "-m", f"RESTORE to {target_hash[:8]}"], cwd=repo_path)
        logger.info(f"/set_good_branch - Successful connection from {current_user.id} at {request.remote_addr}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.info(f"/set_good_branch - Successful connection from {current_user.id} at {request.remote_addr}. Failed to execute git: {str(e)}")
        return jsonify({"error": str(e)}), 500