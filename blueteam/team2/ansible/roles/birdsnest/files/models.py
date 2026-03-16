from flask_sqlalchemy import SQLAlchemy
import time
from datetime import datetime
from sqlalchemy import func
from shared import (
setup_logging, User, CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, STALE_TIME, DEFAULT_WEBHOOK_SLEEP_TIME,
MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL, INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, AUTHCONFIG_STRICT_IP,
AUTHCONFIG_STRICT_USER, AUTHCONFIG_CREATE_INCIDENT, AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL, CREATE_TEST_DATA, SECRET_KEY,
GIT_PROJECT_ROOT, GIT_BACKEND, DATABASE_CREDS, DATABASE_LOCATION, DATABASE_DB
)
db = SQLAlchemy()
logger = setup_logging()
class Agent(db.Model):
    __tablename__ = 'agents'
    agent_id = db.Column(db.String(65), primary_key=True, nullable=False)
    agent_name = db.Column(db.String(128))
    agent_type = db.Column(db.String(24))
    hostname = db.Column(db.String(128))
    ip = db.Column(db.String(45)) 
    os = db.Column(db.String(64))
    executionUser = db.Column(db.String(128))
    executionAdmin = db.Column(db.Boolean, default=False)
    lastSeenTime = db.Column(db.Integer, default=lambda: int(time.time())) 
    lastStatus = db.Column(db.Boolean, default=True) 
    stale = db.Column(db.Boolean, default=False)
    pausedUntil = db.Column(db.String(32), default=0) 
    messages = db.relationship('Message', backref='agent', lazy='dynamic', primaryjoin="Agent.agent_id == Message.agent_id")
    incidents = db.relationship('Incident', backref='agent', lazy='dynamic', primaryjoin="Agent.agent_id == Incident.agent_id")
    auth_token_agents = db.relationship('AuthTokenAgent', backref='agent', lazy='dynamic', primaryjoin="Agent.agent_id == AuthTokenAgent.agent_id")
    agent_tasks = db.relationship('AgentTask', backref='agent', lazy='select', primaryjoin="Agent.agent_id == AgentTask.agent_id")
    system_users = db.relationship('SystemUser', backref='agent', lazy='select', primaryjoin="Agent.agent_id == SystemUser.agent_id")
    def __repr__(self):
        return f"<Agent {self.agent_name} ({'Online' if self.lastStatus else 'Down'})>"
class Message(db.Model):
    __tablename__ = 'messages'
    message_id = db.Column(db.String(128), primary_key=True, nullable=False)
    agent_id = db.Column(db.String(65), db.ForeignKey('agents.agent_id'), nullable=False)
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    oldStatus = db.Column(db.Boolean, nullable=False)
    newStatus = db.Column(db.Boolean, nullable=False)
    message = db.Column(db.Text, nullable=False) 
    def __repr__(self):
        return f"<Message {self.timestamp} from {self.agent_id}>"
class Incident(db.Model):
    __tablename__ = 'incidents'
    incident_id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    agent_id = db.Column(db.String(65), db.ForeignKey('agents.agent_id'), nullable=False)
    tag = db.Column(db.String(10), default="New", nullable=False) 
    oldStatus = db.Column(db.Boolean, nullable=False)
    newStatus = db.Column(db.Boolean, nullable=False)
    message = db.Column(db.Text, nullable=False)
    assignee = db.Column(db.String(128))
    sla = db.Column(db.Integer) 
    def __repr__(self):
        return f"<Incident {self.incident_id} for {self.agent_id} (Tag: {self.tag})>"
class AuthToken(db.Model):
    __tablename__ = 'auth_tokens'
    token = db.Column(db.String(128), primary_key=True, nullable=False) 
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    added_by = db.Column(db.String(128))
    def __repr__(self):
        return f"<AuthToken {self.token[:8]}...>"
class AuthTokenAgent(db.Model):
    __tablename__ = 'auth_tokens_agent'
    token = db.Column(db.String(128), primary_key=True, nullable=False) 
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    added_by = db.Column(db.String(128))
    agent_id = db.Column(db.String(65), db.ForeignKey('agents.agent_id'), nullable=False)
    def __repr__(self):
        return f"<AuthToken {self.token[:8]}...>"
class WebUser(db.Model):
    __tablename__ = 'web_users'
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    password = db.Column(db.String(192), nullable=False) 
    role = db.Column(db.String(20), nullable=False) 
    def __repr__(self):
        return f"<WebUser {self.username} (Role: {self.role})>"
class AnsibleResult(db.Model):
    __tablename__ = 'ansible_results'
    task = db.Column(db.Integer, primary_key=True, nullable=False)
    returncode = db.Column(db.Integer, nullable=False)
    result = db.Column(db.String(4096), nullable=False) 
    def __repr__(self):
        return f"<Ansible Task {self.task} (ReturnCode: {self.returncode}, Result: {self.result})>"
    def to_dict(self):
        data = {
            'task': self.task,
            'returncode': self.returncode,
            'result': self.result,
        }
        return data
class AnsibleVars(db.Model):
    __tablename__ = 'ansiblevars'
    id = db.Column(db.String(32),primary_key=True, nullable=False)
    dest_ip = db.Column(db.String(64), default="192.168.1.1", nullable=False)
    ansible_folder = db.Column(db.String(256), default="~/ansible/", nullable=False)
    ansible_playbook = db.Column(db.String(64), default="playbook.yaml", nullable=False)
    ansible_inventory = db.Column(db.String(64), default="inventory.yaml", nullable=False)
    ansible_venv = db.Column(db.String(256), default="", nullable=False)
    ansible_user = db.Column(db.String(64), default="", nullable=False)
    ansible_port = db.Column(db.Integer, default=22, nullable=False)
    ansible_password = db.Column(db.String(256), default="", nullable=False)
    ansible_become_password = db.Column(db.String(256), default="", nullable=False)
    magpie_deploy_dir_win = db.Column(db.String(512), default="C:\\magpie", nullable=False)
    magpie_deploy_dir_unix = db.Column(db.String(512), default="/magpie", nullable=False)
    magpie_agent_executable = db.Column(db.String(128), default="agent_Windows_10.exe", nullable=False)
    magpie_tester_executable = db.Column(db.String(128), default="agent_tester_Windows_10.exe", nullable=False)
    magpie_task_name = db.Column(db.String(32), default="magpie", nullable=False)
    magpie_task_interval = db.Column(db.Integer, default=60, nullable=False)
    magpie_task_create = db.Column(db.Boolean, default=True, nullable=False)
    magpie_include_tester = db.Column(db.Boolean, default=True, nullable=False)
    magpie_agent_name = db.Column(db.String(32), default="", nullable=False)
    magpie_auth_token = db.Column(db.String(128), default="testtoken", nullable=False)
    magpie_agent_type = db.Column(db.String(32), default="magpie", nullable=False)
    magpie_server_url = db.Column(db.String(128), default="https://127.0.0.1:8000/", nullable=False)
    magpie_server_timeout = db.Column(db.Integer, default=5, nullable=False)
    magpie_sleeptime = db.Column(db.Integer, default=60, nullable=False)
    magpie_disarm = db.Column(db.Boolean, default=True, nullable=False)
    magpie_debug_print = db.Column(db.Boolean, default=True, nullable=False)
    magpie_logfile = db.Column(db.String(256), default="log.txt", nullable=False)
    magpie_backupdir = db.Column(db.String(256), default="", nullable=False)
    magpie_mtu_min = db.Column(db.Integer, default=1200, nullable=False)
    magpie_mtu_default = db.Column(db.Integer, default=1300, nullable=False)
    magpie_mtu_max = db.Column(db.Integer, default=1514, nullable=False)
    magpie_linux_default_ttl = db.Column(db.Integer, default=64, nullable=False)
    magpie_ports = db.Column(db.String(256), default="[81]", nullable=False)
    magpie_services = db.Column(db.String(256), default='["AxInstSV"]', nullable=False)
    magpie_packages = db.Column(db.String(256), default='[""]', nullable=False)
    magpie_service_backups = db.Column(db.String(1024), default='{"PathName":"C:\\Windows\\system32\\svchost.exe -k AxInstSVGroup", "StartName":"LocalSystem", "Dependencies":null, "DisplayName":"ActiveX Installer (AxInstSV)", "StartType": "Manual"}', nullable=False)
    def __repr__(self):
        return f"<Ansible Defaults for Profile {self.id}>"
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
class AuthConfig(db.Model):
    __tablename__ = 'authconfigs'
    id = db.Column(db.Integer, primary_key=True)
    entity_value = db.Column(db.String(100), nullable=False, unique=True)
    entity_type = db.Column(db.String(10), nullable=False) 
    disposition = db.Column(db.String(10), nullable=False) 
    def to_dict(self):
        return {
            "value": self.entity_value,
            "type": self.entity_type,
            "status": self.disposition
        }
    def __repr__(self):
        return f"<AuthConfig {self.id}: {self.entity_type} {self.entity_value} is classified as {self.disposition}.>"
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
class AuthConfigGlobal(db.Model):
    __tablename__ = 'authconfigglobals'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Boolean, default=False)
class AuthRecord(db.Model):
    __tablename__ = 'authrecords'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(128), db.ForeignKey('messages.message_id'), nullable=False)
    agent_id = db.Column(db.String(65), db.ForeignKey('agents.agent_id'), nullable=False)
    user = db.Column(db.String(100), nullable=False)
    login_type = db.Column(db.String(32), nullable=False)
    srcip = db.Column(db.String(45), default="", nullable=False) 
    successful = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.Integer, nullable=False) 
    notes = db.Column(db.String(1024))
    def __repr__(self):
        status = "Success" if self.successful else "Failed"
        if self.notes:
            return f"<AuthRecord {self.id}: {self.login_type} login attempt on user {self.user} from {self.srcip} ({status}). Notes: {self.notes}>"
        return f"<AuthRecord {self.id}: {self.login_type} login attempt on user {self.user} from {self.srcip} ({status}).>"
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
class WebhookQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.incident_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class AnsibleQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ansible_folder = db.Column(db.String(255), nullable=False)
    ansible_playbook = db.Column(db.String(255), nullable=False)
    ansible_inventory = db.Column(db.String(255), nullable=False)
    dest_ip = db.Column(db.String(50), nullable=False)
    ansible_venv = db.Column(db.String(255), nullable=True)
    extra_vars = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class AgentTask(db.Model):
    __tablename__ = 'agent_tasks'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(65), db.ForeignKey('agents.agent_id'), nullable=False)
    local_index = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    task = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text, default="", nullable=False)
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.local_index is None:
            last_index = db.session.query(func.max(AgentTask.local_index)).filter(
                AgentTask.agent_id == self.agent_id
            ).scalar()
            self.local_index = (last_index or 0) + 1
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
class SystemUser(db.Model):
    __tablename__ = 'system_users'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(65), db.ForeignKey('agents.agent_id'), nullable=False)
    local_index = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(64), nullable=False)
    admin = db.Column(db.Boolean, nullable=False)
    locked = db.Column(db.Boolean, nullable=False)
    last_login = db.Column(db.Integer, nullable=False)
    account_type = db.Column(db.String(8), nullable=False)
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.local_index is None:
            last_index = db.session.query(func.max(SystemUser.local_index)).filter(
                SystemUser.agent_id == self.agent_id
            ).scalar()
            self.local_index = (last_index or 0) + 1
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}