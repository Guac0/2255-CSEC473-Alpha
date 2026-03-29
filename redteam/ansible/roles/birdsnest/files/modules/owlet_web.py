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
def list_authconfig():
    logger.info(f"/list_authconfig - Successful connection from {current_user.id} at {request.remote_addr}.")
    entries = AuthConfig.query.all()
    return jsonify([entry.to_dict() for entry in entries])
def list_auth_records():
    logger.info(f"/list_auth_records - Successful connection from {current_user.id} at {request.remote_addr}.")
    results = db.session.query(AuthRecord, Agent).        join(Agent, AuthRecord.agent_id == Agent.agent_id).        order_by(AuthRecord.timestamp.desc()).all()
    data = {}
    for record, agent in results:
        entry = record.to_dict()
        entry.pop('agent_id', None)
        entry['hostname'] = agent.hostname
        entry['agent_ip'] = agent.ip  
        entry['os'] = agent.os
        data[str(record.id)] = entry
    return jsonify(data)
def update_global_config():
    data = request.get_json()
    key = data.get('key')
    config = AuthConfigGlobal.query.filter_by(key=key).first()
    if not config:
        config = AuthConfigGlobal(key=key, value=data.get('value'))
        db.session.add(config)
    else:
        config.value = data.get('value')
    db.session.commit()
    logger.info(f"/update_global_config - Successful connection from {current_user.id} at {request.remote_addr}. Config change: {key}:{config.value}")
    return jsonify({"status": "success", "key": key, "new_value": config.value})
def add_authconfig():
    data = request.get_json()
    val = data.get('entity_value', '').strip()
    e_type = data.get('entity_type') 
    disp = data.get('disposition')   
    if not val or not e_type or not disp:
        return jsonify({"status": "error", "message": "Missing fields"}), 400
    if AuthConfig.query.filter_by(entity_value=val).first():
        logger.info(f"/add_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. New val already exists: {val}, e_type: {e_type}, disp: {disp}")
        return jsonify({"status": "error", "message": "Entry already exists"}), 409
    new_entry = AuthConfig(entity_value=val, entity_type=e_type, disposition=disp)
    db.session.add(new_entry)
    db.session.commit()
    logger.info(f"/add_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. New val: {val}, e_type: {e_type}, disp: {disp}")
    return jsonify({"status": "success", "id": new_entry.id})
def update_authconfig_status():
    data = request.get_json()
    entry = AuthConfig.query.get(data.get('id'))
    if not entry:
        logger.warning(f"/update_authconfig_status - Failed connection from {current_user.id} at {request.remote_addr}. No value with id {data.get('id')} found")
        return jsonify({"status": "error", "message": "Not found"}), 404
    entry.disposition = "MALICIOUS" if entry.disposition == "LEGITIMATE" else "LEGITIMATE"
    db.session.commit()
    logger.info(f"/update_authconfig_status - Successful connection from {current_user.id} at {request.remote_addr}. Entity: {entry.entity_value}, disposition: {entry.disposition}")
    return jsonify({"status": "success", "new_disposition": entry.disposition})
def delete_authconfig():
    data = request.get_json()
    entry_id = data.get('id')
    entry = AuthConfig.query.get(entry_id)
    if entry:
        logger.info(f"/delete_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Deleting entry {entry.entity_value}")
        db.session.delete(entry)
        db.session.commit()
        return jsonify({"status": "success"})
    logger.warning(f"/delete_authconfig - Failed connection from {current_user.id} at {request.remote_addr}. Entry with id {data.get('id')} not found.")
    return jsonify({"status": "error", "message": "Entry not found"}), 404
def authrecord_update_notes():
    data = request.get_json()
    record_id = data.get('id')
    new_notes = data.get('notes')
    try:
        record = AuthRecord.query.get(record_id)
        if not record:
            logger.warning(f"/authrecord_update_notes - failed request from {current_user.id} at {request.remote_addr} - record not found for id {record_id} and new_notes {new_notes}.")
            return jsonify({"status": "error", "message": "Record not found"}), 404
        record.notes = new_notes
        db.session.commit()
        logger.info(f"/authrecord_update_notes - successful request from {current_user.id} at {request.remote_addr} - updating notes for incident {record_id} to {new_notes}.")
        return jsonify({"status": "success", "message": "Notes updated"})
    except Exception as E:
        db.session.rollback()
        logger.error(f"/authrecord_update_notes - failed request from {current_user.id} at {request.remote_addr} - Database error: {E}")
        return jsonify({"error": "Database error"}), 500
def bulk_authconfig():
    data = request.get_json()
    action = data.get('action') 
    if action == 'export':
        entries = AuthConfig.query.all()
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Exporting config.")
        return jsonify([entry.to_dict() for entry in entries])
    if action == 'import':
        raw_list = data.get('data', [])
        added_count = 0
        for item in raw_list:
            if not AuthConfig.query.filter_by(entity_value=item['entity_value']).first():
                new_entry = AuthConfig(
                    entity_value=item['entity_value'],
                    entity_type=item['entity_type'],
                    disposition=item['disposition']
                )
                db.session.add(new_entry)
                added_count += 1
        db.session.commit()
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Importing config of size {added_count}.")
        return jsonify({"status": "success", "added": added_count})
def bulk_auth_records():
    data = request.get_json()
    action = data.get('action') 
    if action == 'export':
        records = AuthRecord.query.all()
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Exporting records.")
        return jsonify([r.to_dict() for r in records])
    if action == 'import':
        raw_list = data.get('data', [])
        added_count = 0
        for item in raw_list:
            exists = AuthRecord.query.filter_by(
                timestamp=item.get('timestamp'),
                user=item.get('user'),
                srcip=item.get('srcip')
            ).first()
            if not exists:
                new_rec = AuthRecord(
                    timestamp=item.get('timestamp'),
                    agent_id=item.get('agent_id'),
                    user=item.get('user'),
                    srcip=item.get('srcip'),
                    successful=item.get('successful'),
                    notes=item.get('notes', '')
                )
                db.session.add(new_rec)
                added_count += 1
        db.session.commit()
        logger.info(f"/bulk_authconfig - Successful connection from {current_user.id} at {request.remote_addr}. Importing records of size {added_count}.")
        return jsonify({"status": "success", "added": added_count})
def get_global_config_web():
    logger.info(f"/web/list_authconfigglobal - Successful connection from {request.remote_addr}.")
    configs = AuthConfigGlobal.query.all()
    return jsonify({c.key: c.value for c in configs})