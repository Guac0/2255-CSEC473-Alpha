import time
from server import app
from shared import (
CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE,
DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, SECRET_KEY, 
setup_logging)
from models import (
db, AuthToken, WebUser, WebhookQueue, Host,
ScoringUser, ScoringUserList, Service, ScoringHistory, ScoringCriteria, ScoringTeams
)

logger = setup_logging("scoring_worker")

def run_scoring_round():
    with app.app_context():
        # You now have full access to the DB using Flask syntax
        services = Service.query.all()
        logger.info(f"Worker checking {len(services)} services")
        
        for s in services:
            new_entry = ScoringHistory(service_id=s.id, value=1, message="Up")
            db.session.add(new_entry)
        
        db.session.commit()

if __name__ == "__main__":
    logger.info("Scoring worker started")
    while True:
        run_scoring_round()
        time.sleep(60)