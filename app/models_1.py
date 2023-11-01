from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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
