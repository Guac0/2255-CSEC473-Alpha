from flask_login import LoginManager, login_required, logout_user, current_user, current_user
from flask import Flask, request, jsonify, render_template, redirect, url_for, abort, send_from_directory
from functools import wraps
from datetime import timedelta
import time
import os
import subprocess
from werkzeug.middleware.proxy_fix import ProxyFix
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
from modules.generic_web import (
    login,
    dashboard_summary,
    list_users, list_users_simple, list_tokens, list_tokens_agent,
    list_tokens_number, list_tokens_agent_number, list_agents, list_messages,
    list_incidents, list_ansiblevars, list_logfile,
    list_ansibleresult, set_ansiblevars,
    agent_pause, agent_resume, add_incident, add_user,
    delete_token, delete_token_agent, update_incident_tag, update_incident_assignee,
    update_incident_sla, add_ansible, add_token, delete_user,
    get_task, get_tasks_all, add_task, add_task_bulk
)
from modules.generic_agent import (
    beacon_generic_handler, beacon_generic, get_pause,
    get_task_agent, set_task_result
)
from modules.magpie_web import (
    list_git_overall, get_repo_history, get_commit_diff, save_git_note, set_good_branch
)
from modules.magpie_agent import (
    beacon_magpie, git_backend
)
from modules.owlet_web import (
    list_authconfig, list_auth_records, update_global_config, 
    add_authconfig, update_authconfig_status, delete_authconfig, 
    authrecord_update_notes, bulk_authconfig, bulk_auth_records,
    get_global_config_web
)
from modules.owlet_agent import (
    beacon_owlet, get_config, get_global_config_agent
)
from modules.kingfisher_agent import (
    beacon_kingfisher
)
from modules.kingfisher_web import (
    list_system_users, list_system_users_all
)
SQLALCHEMY_DATABASE_URI = f"postgresql+psycopg2://{ DATABASE_CREDS }@{ DATABASE_LOCATION }/{ DATABASE_DB }"
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['SECRET_KEY'] = CONFIG["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.config.update(
    SESSION_COOKIE_SECURE=True, 
    SESSION_COOKIE_HTTPONLY=True, 
    SESSION_COOKIE_SAMESITE="Strict", 
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=3),
    SESSION_REFRESH_EACH_REQUEST=True, 
    SESSION_TYPE='sqlalchemy',
    SESSION_SQLALCHEMY=db,  
    SESSION_SQLALCHEMY_TABLE='flask_sessions', 
    SESSION_PERMANENT=True,
    SESSION_USE_SIGNER=True 
)
db.init_app(app)
@app.errorhandler(Exception)
def handle_exception(e):
    try:
        logger.error(f"{request.path} ({request.endpoint}) - Unhandled top level generic internal server error: {str(e)}")
    except Exception as E:
        logger.error(f"unknown endpoint - Unhandled top level generic internal server error: {str(e)}.\nSecondary error when handling error: {E}")
    return "Generic Internal Server Error", 500
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_redirect'  
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"
create_db_tables(app)
logger = setup_logging("web",app)
logger.info(f"Starting server on {HOST}:{PORT}")
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)  
        return f(*args, **kwargs)
    return decorated_function
def analyst_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.role != "analyst" and current_user.role != "admin" ):
            abort(403)  
        return f(*args, **kwargs)
    return decorated_function
@login_manager.user_loader
def load_user(id):
    user_record = WebUser.query.filter(WebUser.username == id).first()
    if user_record:
        return User(id, user_record.role)
    return None
@app.route("/")
@app.route("/web/")
@app.route("/web/dashboard")
@login_required
def page_dashboard():
    logger.info(f"/dashboard - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("dashboard.html")
@app.route("/web/agents")
@login_required
def page_agents():
    logger.info(f"/agents - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("agents.html")
@app.route("/web/messages")
@login_required
def page_messages():
    logger.info(f"/messages - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("messages.html")
@app.route("/web/configmgmt")
@login_required
def page_configmgmt():
    logger.info(f"/configmgmt - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("configmgmt.html")
@app.route("/web/deployment")
@login_required
@analyst_required
def page_deployment():
    logger.info(f"deployment - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("deployment.html")
@app.route("/web/incidents")
@login_required
def page_incidents():
    logger.info(f"/incidents - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("incidents.html")
@app.route("/web/management")
@login_required
@admin_required
def page_management():
    logger.info(f"management - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("management.html")
@app.route("/web/users")
@login_required
def page_users():
    logger.info(f"users - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("users.html")
@app.route("/web/tasks")
@login_required
@admin_required
def page_tasks():
    logger.info(f"tasks - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("tasks.html")
@app.route("/web/authrecords")
@login_required
def page_authrecords():
    logger.info(f"/authrecords - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("authrecords.html")
@app.route("/web/authconfig")
@login_required
@analyst_required
def page_authconfig():
    logger.info(f"/authconfig - Successful connection from {current_user.id} at {request.remote_addr}")
    return render_template("authconfig.html")
@app.route('/web/favicon.ico')
def favicon():
    logger.info(f"favicon.ico - Successful connection at {request.remote_addr}")
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico',mimetype='image/vnd.microsoft.icon')
@app.route('/web/background.jpg')
def background():
    logger.info(f"/background.jpg - Successful connection at {request.remote_addr}")
    return send_from_directory(os.path.join(app.root_path, 'static'),'background.jpg',mimetype='image/vnd.microsoft.icon')
@app.route('/web/login', methods=['GET', 'POST'])
def login_redirect():
    return login()
@app.route('/web/logout')
@login_required
def logout():
    logger.info(f"/logout - Logging out user {current_user.id} at {request.remote_addr}")
    logout_user()
    return redirect(url_for('login_redirect'))
@app.route('/web/whoami')
@login_required
def whoami():
    logger.info(f"/whoami - Successful connection for {current_user.id} at {request.remote_addr}")
    return jsonify({"username": current_user.id, "role": current_user.role})
@app.route('/web/ip')
@login_required
def ip_web():
    logger.info(f"/web/ip - Successful connection for {current_user.id} at {request.remote_addr}")
    return {
        "remote_addr": request.remote_addr,
        "x_forwarded_for": request.headers.get('X-Forwarded-For'),
        "environ_remote_addr": request.environ.get('REMOTE_ADDR')
    }
@app.route('/web/exception')
@login_required
def exception_web():
    logger.info(f"/web/exception - Successful connection for {current_user.id} at {request.remote_addr}")
    raise Exception("test web exception")
@app.route("/agent/ping", methods=["POST"])
def ping():
    logger.info(f"/ping - Successful connection from {request.remote_addr}")
    return "ok", 200
@app.route("/agent/beacon", methods=["POST"])
def beacon_generic_redirect():
    return beacon_generic_handler()
@app.route("/agent/beacon/magpie", methods=["POST"])
def beacon_magpie_redirect():
    return beacon_magpie()
@app.route("/agent/beacon/owlet", methods=["POST"])
def beacon_owlet_redirect():
    return beacon_owlet()
@app.route("/agent/beacon/kingfisher", methods=["POST"])
def beacon_kingfisher_redirect():
    return beacon_kingfisher()
@app.route("/agent/get_pause", methods=["POST"])
def get_pause_redirect():
    return get_pause()
@app.route("/agent/get_task", methods=["POST"])
def get_task_agent_redirect():
    return get_task_agent()
@app.route("/agent/set_task_result", methods=["POST"])
def set_task_result_redirect():
    return set_task_result()
@app.route('/agent/list_authconfig_agent', methods=['POST'])
def get_config_redirect():
    return get_config()
@app.route('/agent/list_authconfigglobal', methods=['POST'])
def get_global_config_agent_redirect():
    return get_global_config_agent()
@app.route('/agent/git/<repo_name>.git/<path:git_path>', methods=['GET', 'POST', 'PROPFIND'])
@app.route('/agent/git/<repo_name>.git/', defaults={'git_path': ''}, methods=['GET', 'POST', 'PROPFIND'])
def git_backend_redirect(repo_name, git_path):
    return git_backend(repo_name, git_path)
@app.route('/agent/ip')
@login_required
def ip_agent():
    logger.info(f"/agent/ip - Successful connection for {current_user.id} at {request.remote_addr}")
    return {
        "remote_addr": request.remote_addr,
        "x_forwarded_for": request.headers.get('X-Forwarded-For'),
        "environ_remote_addr": request.environ.get('REMOTE_ADDR')
    }
@app.route('/agent/exception')
@login_required
def exception_agent():
    logger.info(f"/agent/exception - Successful connection at {request.remote_addr}")
    raise Exception("test agent exception")
@app.route('/web/list_authconfigglobal', methods=['POST'])
@login_required
def get_global_config_web_redirect():
    return get_global_config_web()
@app.route("/web/dashboard_summary", methods=["POST"])
@login_required
def dashboard_summary_redirect():
    return dashboard_summary()
@app.route("/web/get_repo_history", methods=["POST"])
@login_required
def get_repo_history_redirect():
    return get_repo_history()
@app.route("/web/get_commit_diff", methods=["POST"])
@login_required
def get_commit_diff_redirect():
    return get_commit_diff()
@login_required
@app.route('/web/list_authconfig', methods=['POST'])
def list_authconfig_redirect():
    return list_authconfig()
@login_required
@app.route('/web/list_auth_records', methods=['POST'])
def list_auth_records_redirect():
    return list_auth_records()
@login_required
@app.route("/web/list_git_overall", methods=["POST"])
def list_git_overall_redirect():
    return list_git_overall()
@login_required
@app.route("/web/ping_login", methods=["POST"])
def ping_login():
    logger.info(f"/ping_login - Successful connection from {current_user.id} at {request.remote_addr}")
    return "ok", 200
@app.route("/web/list_users", methods=["POST"])
@login_required
@admin_required
def list_users_redirect():
    return list_users()
@app.route("/web/list_users_simple", methods=["POST"])
@login_required
def list_users_simple_redirect():
    return list_users_simple()
@app.route("/web/list_tokens", methods=["POST"])
@login_required
@admin_required
def list_tokens_redirect():
    return list_tokens()
@app.route("/web/list_tokens_number", methods=["POST"])
@login_required
def list_tokens_number_redirect():
    return list_tokens_number()
@app.route("/web/list_tokens_agent", methods=["POST"])
@login_required
@admin_required
def list_tokens_agent_redirect():
    return list_tokens_agent()
@app.route("/web/list_tokens_agent_number", methods=["POST"])
@login_required
def list_tokens_agent_number_redirect():
    return list_tokens_agent_number()
@app.route("/web/list_agents", methods=["POST"])
@login_required
def list_agents_redirect():
    return list_agents()
@app.route("/web/list_messages", methods=["POST"])
@login_required
def list_messages_redirect():
    return list_messages()
@app.route("/web/list_incidents", methods=["POST"])
@login_required
def list_incidents_redirect():
    return list_incidents()
@app.route("/web/list_ansiblevars", methods=["GET"]) 
@login_required
def list_ansiblevars_redirect():
    return list_ansiblevars()
@app.route("/web/list_logfile", methods=["POST"])
@login_required
@admin_required
def list_logfile_redirect(filepath=LOGFILE, lines=50):
    return list_logfile(filepath, lines)
@app.route("/web/list_ansibleresult", methods=["POST"])
@login_required
@analyst_required
def list_ansibleresult_redirect():
    return list_ansibleresult()
@app.route("/web/get_task", methods=["POST"])
@login_required
def get_tasks_all_redirect():
    return get_tasks_all()
@app.route("/web/get_tasks_all", methods=["POST"])
@login_required
def get_task_redirect():
    return get_task()
@app.route("/web/list_system_users", methods=["POST"])
@login_required
def list_system_users_redirect():
    return list_system_users()
@app.route("/web/list_system_users_all", methods=["POST"])
@login_required
def list_system_users_all_redirect():
    return list_system_users_all()
@app.route("/web/set_ansiblevars", methods=["POST"])
@login_required
@analyst_required
def set_ansiblevars_redirect():
    return set_ansiblevars()
@app.route("/web/save_git_note", methods=["POST"])
@login_required
@analyst_required
def save_git_note_redirect():
    return save_git_note()
@app.route("/web/set_good_branch", methods=["POST"])
@login_required
@analyst_required
def set_good_branch_redirect():
    return set_good_branch()
@app.route('/web/update_authconfigglobal', methods=['POST'])
@login_required
@analyst_required
def update_global_config_redirect():
    return update_global_config()
@app.route('/web/add_authconfig', methods=['POST'])
@login_required
@analyst_required
def add_authconfig_redirect():
    return add_authconfig()
@app.route('/web/update_authconfig_status', methods=['POST'])
@login_required
@analyst_required
def update_authconfig_status_redirect():
    return update_authconfig_status()
@app.route('/web/delete_authconfig', methods=['POST'])
@login_required
@analyst_required
def delete_authconfig_redirect():
    return delete_authconfig()
@app.route('/web/authrecord_update_notes', methods=['POST'])
@login_required
@analyst_required
def authrecord_update_notes_redirect():
    return authrecord_update_notes()
@app.route('/web/bulk_authconfig', methods=['POST'])
@login_required
@analyst_required
def bulk_authconfig_redirect():
    return bulk_authconfig()
@app.route('/web/bulk_auth_records', methods=['POST'])
@login_required
@analyst_required
def bulk_auth_records_redirect():
    return bulk_auth_records()
@app.route("/web/agent_pause", methods=["POST"])
@login_required
@analyst_required
def agent_pause_redirect():
    return agent_pause()
@app.route("/web/agent_resume", methods=["POST"])
@login_required
@analyst_required
def agent_resume_redirect():
    return agent_resume()
@app.route("/web/add_incident", methods=["POST"])
@login_required
@analyst_required
def add_incident_redirect():
    return add_incident()
@app.route("/web/add_user", methods=["POST"])
@login_required
@admin_required
def add_user_redirect():
    return add_user()
@app.route("/web/delete_user", methods=["POST"])
@login_required
@admin_required
def delete_user_redirect():
    return delete_user()
@app.route("/web/add_token", methods=["POST"])
@login_required
@admin_required
def add_token_redirect():
    return add_token()
@app.route("/web/delete_token", methods=["POST"])
@login_required
@admin_required
def delete_token_redirect():
    return delete_token()
@app.route("/web/delete_token_agent", methods=["POST"])
@login_required
@admin_required
def delete_token_agent_redirect():
    return delete_token_agent()
@app.route("/web/update_incident_tag", methods=["POST"])
@login_required
@analyst_required
def update_incident_tag_redirect():
    return update_incident_tag()
@app.route("/web/update_incident_assignee", methods=["POST"])
@login_required
@analyst_required
def update_incident_assignee_redirect():
    return update_incident_assignee()
@app.route("/web/update_incident_sla", methods=["POST"])
@login_required
@analyst_required
def update_incident_sla_redirect():
    return update_incident_sla()
@app.route("/web/add_ansible", methods=["POST"])
@login_required
@analyst_required
def add_ansible_redirect():
    return add_ansible()
@app.route("/web/add_task", methods=["POST"])
@login_required
@analyst_required
def add_task_redirect():
    return add_task()
@app.route("/web/add_task_bulk", methods=["POST"])
@login_required
@analyst_required
def add_task_bulk_redirect():
    return add_task_bulk()
def start_server():
    app.run(host=HOST, port=PORT, ssl_context='adhoc', use_reloader=False, debug=False)
if __name__ == "__main__":
    start_server()