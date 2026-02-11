from flask_sqlalchemy import SQLAlchemy
from shared import SAVEFILE
import time, datetime

db = SQLAlchemy()

class AuthToken(db.Model):
    __tablename__ = 'auth_tokens'
    
    token = db.Column(db.String(128), primary_key=True, nullable=False) # The token string itself
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    added_by = db.Column(db.String(128))

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    def __repr__(self):
        return f"<AuthToken {self.token[:8]}...>"

class WebUser(db.Model):
    __tablename__ = 'web_users'
    
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    password = db.Column(db.String(64), nullable=False) 
    role = db.Column(db.String(20), nullable=False) # "admin", "analyst", or "guest"

    def __repr__(self):
        return f"<WebUser {self.username} (Role: {self.role})>"

class WebhookQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Host(db.Model):
    """
    Records each host in the network that has scored service(s) on them.
    
    Relationships:
    one:many with scoringusers
    one:many with services
    one:many with scoringcriteria
    """
    __tablename__ = 'hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    os = db.Column(db.String(32), nullable=False)

    scoringusers = db.relationship('ScoringUser', backref='host')
    services = db.relationship('Service', backref='host')
    scoringcriteria = db.relationship('ScoringCriteria', backref='host')

    def __repr__(self):
        return f"<Host {self.hostname}, IP {self.ip}, OS {self.os}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringTeams(db.Model):
    """
    Records each team and their score

    Relationships:
    one:many with scoring histories
    """
    __tablename__ = 'scoring_teams'

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    team_name = db.Column(db.String(10), nullable=False)
    score = db.Column(db.Integer, nullable=False, default=0)
    multiplier = db.Column(db.Integer, nullable=False, default=1)

    scoringhistories = db.relationship('ScoringHistory', backref='scoringteam')

    def __repr__(self):
        return f"<ScoringTeam {self.team_name}, id {self.id}, score {self.score}>"
    def to_dict(self):
         return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringUser(db.Model):
    """
    Records each user:password combo for each host
    Each host has a unique set of users, although some may same usernames/passwords between hosts
    
    Relationships:
    many:one with hosts
    many:many with scoringuserlists
    """
    __tablename__ = 'scoring_users'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64))

    scoringuserlists = db.relationship('ScoringUserList', backref='scoringuser')

    def __repr__(self):
        return f"<ScoringUser {self.username}@{self.host_id}>"
    def to_dict(self):
        #return {"hostname": self.hostname,"username": self.username} # no password
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringUserList(db.Model):
    """
    Maps several ScoringUsers to one ScoringCriteria instance.
    Each entry has one ScoringUser and one ScoringCriteria, but ScoringCriteria has several entries in ScoringUserList.
    
    Relationships:
    one:one with ScoringUser
    many:one with ScoringCriteria
    """
    __tablename__ = 'scoring_user_lists'

    id = db.Column(db.Integer, primary_key=True)
    criteria_id = db.Column(db.Integer, db.ForeignKey('scoring_criterias.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('scoring_users.id'), nullable=False)

    def __repr__(self):
        return f"<ScoringUserList Index: {self.index}, User: {self.username}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Service(db.Model):
    """
    Records each Service that is scored.
    Scoring criteria(s) is recorded in ScoringCriteria, and results in ScoringHistory.

    Relationships:
    one:one with ScoringHistory
    one:many with ScoringCriteria
    """
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    scorecheck_name = db.Column(db.String(64), index=True, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    
    scoringhistories = db.relationship('ScoringHistory', backref='service')
    scoringcriterias = db.relationship('ScoringCriteria', backref='service')

    def __repr__(self):
        return f"<Service Scorecheck: {self.scorecheck_name}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringHistory(db.Model):
    """
    Records the scoring state for each round. One round occurs every minute.
    During each round, the scoring worker assesses the state of each scorecheck (online or offline)
    using the criteria in ScoringCriteria and loads each service's result into a separate entry in ScoringHistory.
    
    Relationships:
    many:one with Services
    """
    __tablename__ = 'scoring_histories'

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), index=True, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), index=True, nullable=False)
    round = db.Column(db.Integer, index=True, nullable=False)
    value = db.Column(db.Integer, db.ForeignKey('scoring_teams.id'), nullable=False)
    message = db.Column(db.String(128), nullable=False)

    __table_args__ = (
        # Optimizes 'Get all services for one round'
        db.Index('idx_round_service', 'round', 'service_id'),
    )

    def __repr__(self):
        return f"<ScoringHistory Round: {self.round}, Service_id: {self.service_id}, Value: {self.value}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ScoringCriteria(db.Model):
    """
    Records the scoring criteria for a particular service.
    A service may have multiple scoring criterias; only one needs to be satisfied for the scorecheck to succeed.

    Relationships:
    many:one with hosts
    many:one with services
    one:many with user lists
    """
    __tablename__ = 'scoring_criterias'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'))
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'))
    #userlist_index = db.Column(db.Integer, index=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(128), nullable=False)
    team = db.Column(db.Integer, nullable=False)

    scoringuserlist = db.relationship('ScoringUserList', backref='scoringcriteria')

    def __repr__(self):
        return f"<ScoringCriteria Host: {self.host_id}, Scorecheck: {self.service_id}>"
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

