import os, json, logging
from datetime import datetime, timedelta
from concurrent_log_handler import ConcurrentRotatingFileHandler
import platform
from pathlib import Path
from flask_login import UserMixin
import sys
CONFIG_DEFAULTS = {
    "HOST": "0.0.0.0",
    "PORT": 8000,
    "PUBLIC_URL": "https://{HOST}:{PORT}",
    "LOGFILE": "log_{timestamp}.txt",
    "SECRET_KEY": "changemeplease",
    "STALE_TIME": 300,
    "DEFAULT_WEBHOOK_SLEEP_TIME": 0.25,
    "MAX_WEBHOOK_MSG_PER_MINUTE": 50,
    "WEBHOOK_URL": "",
    "CREATE_TEST_DATA": True,
    "DATABASE_CREDS": "birdsnest:birdsnestpwd",
    "DATABASE_LOCATION": "database:5432",
    "DATABASE_DB": "birdsnestdb",
    "AUTHCONFIG_STRICT_IP": False,
    "AUTHCONFIG_STRICT_USER": False,
    "AUTHCONFIG_CREATE_INCIDENT": False,
    "AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL": True,
    "AGENT_AUTH_TOKENS": {
        "testtoken": { 
            "added_by": "default"
        }
    },
    "WEBGUI_USERS": {
        "admin": {"password": "admin", "role": "admin"},
        "analyst": {"password": "analyst", "role": "analyst"},
        "guest": {"password": "guest", "role": "guest"}
    }
}
def load_config(path):
    config = CONFIG_DEFAULTS.copy()
    badPath = False
    if os.path.exists(path):
        with open(path, "r") as f:
            config.update(json.load(f))
    else:
        badPath = True
    now = datetime.now()
    next_minute = (now + timedelta(minutes=1)).replace(second=0, microsecond=0)
    timestamp = next_minute.strftime("%Y-%m-%d_%H-%M-00")
    for key, value in config.items():
        if isinstance(value, str):
            config[key] = value.format(
                HOST=config.get("HOST"),
                PORT=config.get("PORT"),
                timestamp=timestamp
            )
    if badPath:
        print(f"[-] {timestamp} load_config(): config file path not found: {path}")
        with open(config.get("LOGFILE"), "a") as f: 
            f.write(f"[{timestamp}] CRITICAL - load_config(): config file path not found: {path}")
    return config
CONFIG = load_config("config.json") 
HOST = CONFIG["HOST"]
PORT = CONFIG["PORT"]
PUBLIC_URL = CONFIG["PUBLIC_URL"]
LOGFILE = CONFIG["LOGFILE"]
STALE_TIME = CONFIG["STALE_TIME"]
DEFAULT_WEBHOOK_SLEEP_TIME = CONFIG["DEFAULT_WEBHOOK_SLEEP_TIME"]
MAX_WEBHOOK_MSG_PER_MINUTE = CONFIG["MAX_WEBHOOK_MSG_PER_MINUTE"]
WEBHOOK_URL = CONFIG["WEBHOOK_URL"]
INITIAL_AGENT_AUTH_TOKENS = CONFIG["AGENT_AUTH_TOKENS"]
INITIAL_WEBGUI_USERS = CONFIG["WEBGUI_USERS"]
DATABASE_CREDS = CONFIG["DATABASE_CREDS"]
DATABASE_LOCATION = CONFIG["DATABASE_LOCATION"]
DATABASE_DB = CONFIG["DATABASE_DB"]
AUTHCONFIG_STRICT_IP = CONFIG["AUTHCONFIG_STRICT_IP"]
AUTHCONFIG_STRICT_USER = CONFIG["AUTHCONFIG_STRICT_USER"]
AUTHCONFIG_CREATE_INCIDENT = CONFIG["AUTHCONFIG_CREATE_INCIDENT"]
AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL = CONFIG["AUTHCONFIG_LOG_ATTEMPT_SUCCESSFUL"]
CREATE_TEST_DATA = CONFIG["CREATE_TEST_DATA"]
SECRET_KEY = CONFIG["SECRET_KEY"]
if "windows" in platform.system().lower():
    GIT_BACKEND = "C:/Program Files/Git/mingw64/libexec/git-core/git-http-backend.exe"
else:
    GIT_BACKEND = "/usr/lib/git-core/git-http-backend"
GIT_PROJECT_ROOT = os.path.join(os.path.dirname(Path(__file__).resolve()),"repos")
if not os.path.exists(GIT_PROJECT_ROOT):
    os.mkdir(GIT_PROJECT_ROOT)
def setup_logging(argname="default"): 
    context = os.environ.get("APP_CONTEXT", "DEFAULT")
    name = context
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = ConcurrentRotatingFileHandler(
        LOGFILE,        
        "a",              
        10 * 1024 * 1024, 
        10,               
        encoding='utf-8'
    )
    stream_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '[%(asctime)s] [%(name)s] [%(process)d] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.addHandler(stream_handler)
    logger.propagate = False
    if context == "SERVER":
        gunicorn_logger = logging.getLogger("gunicorn.error")
        gunicorn_logger.addHandler(handler)
    logging.getLogger().addHandler(stream_handler)
    return logger
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role