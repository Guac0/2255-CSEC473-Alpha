from models import (
db, AuthToken, WebUser, WebhookQueue, Host,
ScoringUser, ScoringUserList, Service, ScoringHistory, ScoringCriteria, ScoringTeams
)
from shared import (
CONFIG, HOST, PORT, PUBLIC_URL, LOGFILE, SAVEFILE, CREATE_TEST_DATA,
DEFAULT_WEBHOOK_SLEEP_TIME, MAX_WEBHOOK_MSG_PER_MINUTE, WEBHOOK_URL,
INITIAL_AGENT_AUTH_TOKENS, INITIAL_WEBGUI_USERS, SECRET_KEY, 
setup_logging)
from werkzeug.security import generate_password_hash, check_password_hash
import time
import os
import random

def insert_initial_data(logger):
    """
    Inserts initial configuration data (auth tokens and users) into the database.
    This should only be run after the tables have been created via db.create_all().
    """
    try:
        # --- Insert Agent Auth Tokens ---
        for token_value, data in INITIAL_AGENT_AUTH_TOKENS.items():
            new_token = AuthToken(
                token=token_value,
                timestamp=time.time(),
                added_by=data["added_by"]
            )
            db.session.add(new_token)

        # --- Insert Web Users ---
        for username, data in INITIAL_WEBGUI_USERS.items():
            hashed_password = generate_password_hash(data["password"])
            new_user = WebUser(
                username=username,
                password=hashed_password,
                role=data["role"]
            )
            db.session.add(new_user)
        
        # --- Insert Teams ---
        teams_to_create = ["blue", "red", "offline"]
        team_objs = {}
        for t_name in teams_to_create:
            team = ScoringTeams(
                team_name=t_name,
                score=0,
                multiplier=1
            )
            db.session.add(team)
            team_objs[t_name] = team
        
        db.session.flush() # Get Team IDs

        # --- Parse CSV ---
        raw_csv_data = [
            ("10.0.10.1", "canterlot", "Windows Server 2022", "DNS"),
            ("10.0.10.2", "manehatten", "Windows Server 2022", "MSSQL"),
            ("10.0.10.3", "ponyville", "Debian 13", "Apache2"),
            ("10.0.10.4", "seaddle", "Debian 13", "MariaDB"),
            ("10.0.10.5", "trotsylvania", "Debian 13", "cups"),
            ("10.0.10.6", "crystal-empire", "CachyOS", "vsftpd"),
            ("10.0.20.1", "las-pegasus", "Windows Server 2022", "IIS"),
            ("10.0.20.2", "appleloosa", "Windows Server 2022", "SMB"),
            ("10.0.20.3", "everfree-forest", "Debian 13", "IRC"),
            ("10.0.20.4", "griffonstone", "Debian 13", "Nginx"),
            ("10.0.30.1", "baltamare", "Windows 10", "Workstation"),
            ("10.0.30.2", "neighara-falls", "Windows 10", "Workstation"),
            ("10.0.30.3", "fillydelphia", "Windows CEMeNT", "Workstation"),
            ("10.0.30.4", "cloudsdale", "Ubuntu 24.04", "Workstation"),
            ("10.0.30.5", "vanhoover", "Ubuntu 24.04", "Workstation"),
            ("10.0.30.6", "whinnyapolis", "VoidOS", "Workstation"),
        ]

        scoring_usernames = [
            "twilightsparkle", "applejack", "fluttershy", "rarity", 
            "pinkiepie", "rainbowdash", "spikedragon", "starlightglimmer", 
            "trixielulamoon", "princesscelestia"
        ]

        for ip, hostname, os_name, service_name in raw_csv_data:
            service_name_simple = service_name.lower().strip()
            generic_name="UNKNOWN"
            crit_location=""
            crit_content=""
            if ("dns" in service_name_simple):
                generic_name="dns"
                crit_location=""
                crit_content=""
            elif ("mssql" in service_name_simple):
                generic_name="mssql"
                crit_location="SELECT E.Virtue AS [The Element], C.Name AS [Bearer], C.Species AS [Species], C.LoreTitle AS [Known As], L.PlaceName AS [Resides In], FROM [dbo].[Elements] E JOIN [dbo].[Characters] C ON E.BearerID = C.CharID JOIN [dbo].[Locations] L ON C.HomeLocationID = L.LocationID ORDER BY C.Name;"
                crit_content="" # TODO
            elif ("apache" in service_name_simple):
                generic_name="http"
                crit_location="80"
                crit_content=""
            elif ("mariadb" in service_name_simple):
                generic_name="mariadb"
                crit_location=""
                crit_content=""
            elif ("cups" in service_name_simple):
                generic_name="cups"
                crit_location=""
                crit_content=""
            elif ("vsftpd" in service_name_simple):
                generic_name="ftp"
                crit_location=""
                crit_content=""
            elif ("iis" in service_name_simple):
                generic_name="http"
                crit_location="80"
                crit_content=""
            elif ("smb" in service_name_simple):
                generic_name="smb"
                crit_location=""
                crit_content=""
            elif ("irc" in service_name_simple):
                generic_name="irc"
                crit_location=""
                crit_content=""
            elif ("nginx" in service_name_simple):
                generic_name="http"
                crit_location="80"
                crit_content=""
            elif (("workstation" in service_name_simple) and ("windows" in os_name.lower().strip())):
                generic_name="workstation_windows"
                crit_location=""
                crit_content=""
            elif (("workstation" in service_name_simple) and ("windows" not in os_name.lower().strip())):
                generic_name="workstation_linux"
                crit_location=""
                crit_content=""

            # Create Host
            new_host = Host(
                hostname=hostname,
                ip=ip,
                os=os_name
            )
            db.session.add(new_host)
            db.session.flush()

            # Create Service
            new_service = Service(
                scorecheck_name=generic_name,
                scorecheck_display_name=service_name,
                host=new_host
            )
            db.session.add(new_service)
            db.session.flush()

            # Create Criteria for Blue Team
            new_criteria = ScoringCriteria(
                host=new_host, 
                service=new_service, 
                location=crit_location,
                content=crit_content,
                team_id=team_objs["blue"].id
            )
            db.session.add(new_criteria)
            db.session.flush()

            # Create 10 Users per host and link them to the criteria
            for u_name in scoring_usernames:
                user = ScoringUser(username=u_name, password="FriendshipIsMagic0!", host=new_host)
                db.session.add(user)
                db.session.flush() # Get User ID

                # Map user to criteria (ScoringUserList)
                user_list_entry = ScoringUserList(criteria_id=new_criteria.id, user_id=user.id)
                db.session.add(user_list_entry)

        db.session.commit()
        logger.info(f"Successfully initialized database and inserted initial database values into {SAVEFILE}")

    except Exception as e:
        db.session.rollback()
        logger.fatal(f"Failed to insert initial data into DB: {e}")

def insert_test_rounds(logger, num_rounds=10):
    """
    Inserts dummy scoring history data for 10 rounds.
    Assumes insert_initial_data() has already been run to create hosts/services.
    """
    try:
        logger.info(f"Starting insertion of {num_rounds} rounds of test data...")
        
        # 1. Get all services and teams
        services = Service.query.all()
        blue_team = ScoringTeams.query.filter_by(team_name="blue").first()
        red_team = ScoringTeams.query.filter_by(team_name="red").first()
        offline_team = ScoringTeams.query.filter_by(team_name="offline").first()

        if not services or not blue_team or not offline_team:
            logger.error("Required initial data (services/teams) missing. Run insert_initial_data first.")
            return

        # 2. Loop through rounds
        for round_num in range(1, num_rounds + 1):
            round_entries = []
            
            for service in services:
                # Randomly decide if the service is "Up" or "Down"
                # 50% chance of success (Blue Team), 30% chance of failure (red), 30% offline
                is_up = random.random()
                
                if is_up < 0.4:
                    assigned_team_id = blue_team.id
                    msg = "Legitimate content check succeeded."
                    # Increment the actual team score for realism
                    blue_team.score += 1
                elif is_up > 0.7:
                    assigned_team_id = offline_team.id
                    msg = "Connection timed out / Service unreachable."
                    offline_team.score += 1
                else:
                    assigned_team_id = red_team.id
                    msg = "Malicious content check succeeded."
                    red_team.score += 1

                history_entry = ScoringHistory(
                    service_id=service.id,
                    host_id=service.host_id,
                    round=round_num,
                    value=assigned_team_id,
                    message=msg
                )
                round_entries.append(history_entry)
            
            db.session.add_all(round_entries)
            logger.info(f"Round {round_num}: Inserted {len(round_entries)} service results.")

        # 3. Commit all changes
        db.session.commit()
        logger.info("Successfully committed 10 rounds of test data to the database.")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to insert test rounds: {e}")

def create_db_tables(logger):
    # must be called in app context

    db_exists = os.path.exists(os.path.join("instance",SAVEFILE))
    # This checks the database file defined in SQLALCHEMY_DATABASE_URI.
    # If the file (server.db) doesn't exist, it creates it.
    # If the tables defined in your models don't exist, it creates them.
    db.create_all()
    if not db_exists:
        insert_initial_data(logger)
        if CREATE_TEST_DATA:
            logger.info(f"Inserting test data into database.")
            insert_test_rounds(logger,10)
        #logger.info(f"Initialized database with initial data at {SAVEFILE}")
    else:
        logger.info(f"Initialized database at {SAVEFILE}")