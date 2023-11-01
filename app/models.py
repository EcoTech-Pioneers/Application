import flask
import hashlib
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from flask_login import AnonymousUserMixin, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from . import db, login_manager


class Permission:
    VISIT = 1
    MEMBER = 2
    MODERATE = 4
    ADMIN = 8


@login_manager.user_loader
def load_user(user_id):
    """
    Queries the database for a record of currently logged in user
    Returns User object containing info about logged in user
    """
    return User.query.get(int(user_id))


class Role(db.Model):
    __tablename__ = 'role'
    roleId = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    default = db.Column(db.Boolean, default = False, index = True)
    permissions = db.Column(db.Integer)

    users = db.relationship('User', backref = 'role', lazy = 'dynamic')


    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0


    @staticmethod
    def insert_roles():
        roles = {
                'Guest' : [Permission.VISIT],
                'Member' : [Permission.VISIT, Permission.MEMBER],
                'Administrator' : [Permission.VISIT, Permission.MODERATE, 
                    Permission.MEMBER, Permission.ADMIN]
                }

        default_role = 'Guest'

        for r in roles:
            role = Role.query.filter_by(name = r).first()
            if role in None:
                role = Role(name = r)

            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)

            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()


    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm


    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm


    def reset_permissions(self):
        self.permissions = 0


    def has_permission(self, perm):
        return self.permissions & perm == perm


    def __repr__(self):
        return f"<Role(roleId={self.roleId}, name='{self.name}')>"


class Anonymous_User(AnonymousUserMixin):
    def can(self, permission):
        return False


    def is_administrator(self):
        return False


login_manager.anonymous_user = Anonymous_User


class User(db.Model):
    __tablename__ = 'user'

    userId = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    firstName = db.Column(db.String(40))
    middleName = db.Column(db.String(40))
    lastName = db.Column(db.String(40))
    username = db.Column(db.String(255), nullable=False, unique=True, index=True)
    emailAddress = db.Column(db.String(255), nullable=False, unique=True, index=True)
    phoneNumber = db.Column(db.String(255), nullable=False, unique=True, index=True)
    passwordHash = db.Column(db.String(255), nullable=False)
    imageUrl = db.Column(db.String(255))

    # relationships
    roleId = db.Column(db.Integer, db.ForeignKey('role.roleId'))
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

        # Assign default role to user
        if self.role is None:
            if self.emailAddress == flask.current_app.config['ADMINISTRATOR_EMAIL']:
                self.role = Role.query.filter_by(name = 'Administrator').first()

            if self.role is None:
                self.role = Role.query.filter_by(default = True).first()

        # Generate avatar hash
        if self.emailAddress is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()


    def get_id(self):
        return self.userId

    
    def gravatar_hash(self):
        return hashlib.md5(self.emailAddress.lower().encode('utf-8')).hexdigest()


    def gravatar(self, size = 100, default = 'identicon', rating = 'g'):
        url = 'https://secure.gravatar.com/avatar'
        hash = self.avatar_hash or self.gravatar_hash()
        return "{url}/{hash}?s={size}&d={default}&r={rating}".format(url = url,
                hash = hash, size = size, default = default, rating = rating)

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")


    @password.setter
    def password(self, password):
        self.passwordHash = generate_password_hash(password)


    def verify_password(self, password):
        return check_password_hash(self.passwordHash, password)


    @staticmethod
    def reset_password(token, new_password):
        serializer = Serializer(flask.current_app.config['SECRET_KEY'])
        try:
            data = serializer.loads(token.encode('utf-8'))
        except:
            return False

        user = User.query.get(data.get('reset'))
        if user is None:
            return False

        user.password = new_password
        db.session.add(user)
        return True


    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)


    def is_administrator(self):
        return self.can(Permission.ADMIN)
    

    def register(self, form):
        # Add registration logic here
        pass

    def updateProfile(self, form):
        # Add profile update logic here
        pass

    def login(self, password):
        # Add login logic here
        pass

    def resetPassword(self, newPassword):
        # Add password reset logic here
        pass

    def scheduleEvent(self):
        # Add scheduling event logic here
        pass

    def attendEvent(self):
        # Add attend event logic here
        pass

    def bookEvent(self, eventId):
        # Add book event logic here
        pass

    def unbookEvent(self, eventId):
        # Add unbook event logic here
        pass

    def getAttendedEvents(self):
        # Add logic to retrieve attended events here
        pass

    def addRecord(self, form):
        # Add record creation logic here
        pass

    def getRecords(self):
        # Add logic to retrieve user's records here
        pass

    def confirmRecord(self, recordId):
        # Add record confirmation logic here
        pass

    def revokeRecord(self, recordId):
        # Add record revocation logic here
        pass


class Event(db.Model):
    __tablename__ = 'event'

    eventId = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    imageUrl = db.Column(db.String(255))
    startDateTime = db.Column(db.DateTime)
    endDateTime = db.Column(db.DateTime)
    venue = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    organizer = db.Column(db.String(255))
    isCancelled = db.Column(db.Boolean, default=False)
    dateCreated = db.Column(db.DateTime, default=datetime.utcnow)
    lastUpdated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def getEventDetails(self):
        # Add logic to retrieve event details here
        pass


class Record(db.Model):
    __tablename__ = 'record'

    recordId = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.userId'))
    species = db.Column(db.String(255))
    dateCreated = db.Column(db.DateTime, default=datetime.utcnow)
    datePlanted = db.Column(db.Date)
    numberOfTrees = db.Column(db.Integer)
    imageUrl = db.Column(db.String(255))
    location = db.Column(db.String(255))
    longitude = db.Column(db.Float)
    latitude = db.Column(db.Float)
    lastUpdated = db.Column(db.DateTime, onupdate=datetime.utcnow)
    isConfirmed = db.Column(db.Boolean, default=False)
    isRevoked = db.Column(db.Boolean, default=False)


class RegisteredEvent(db.Model):
    __tablename__ = 'registered_event'

    registeredEventId = db.Column(db.Integer, primary_key=True, autoincrement=True, index=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.userId'))
    eventId = db.Column(db.Integer, db.ForeignKey('event.eventId'))
    isCancelled = db.Column(db.Boolean, default=False)
    isAttended = db.Column(db.Boolean, default=False)
    dateCreated = db.Column(db.DateTime, default=datetime.utcnow)
    lastUpdated = db.Column(db.DateTime, onupdate=datetime.utcnow)
