-- Create the User table
CREATE TABLE IF NOT EXISTS User (
	userId INT AUTO_INCREMENT PRIMARY KEY,
	firstName VARCHAR(32),
	middleName VARCHAR(32),
	lastName VARCHAR(32),
	username VARCHAR(48) NOT NULL UNIQUE,
	emailAddress VARCHAR(128) NOT NULL UNIQUE,
	phoneNumber VARCHAR(20) NOT NULL UNIQUE,
	passwordHash VARCHAR(255) NOT NULL,
	imageUrl VARCHAR(255)
);

-- Create the Event table
CREATE TABLE IF NOT EXISTS Event (
	eventId INT AUTO_INCREMENT PRIMARY KEY,
	title VARCHAR(255),
	description TEXT,
	imageUrl VARCHAR(255),
	startDateTime DATETIME,
	endDateTime DATETIME,
	venue VARCHAR(255),
	latitude DECIMAL(10, 6),
	longitude DECIMAL(10, 6),
	organizer VARCHAR(128),
	isCancelled BOOLEAN DEFAULT false,
	dateCreated DATETIME DEFAULT CURRENT_TIMESTAMP,
	lastUpdated DATETIME ON UPDATE CURRENT_TIMESTAMP
);

-- Create the Record table
CREATE TABLE IF NOT EXISTS Record (
	recordId INT AUTO_INCREMENT PRIMARY KEY,
	userId INT,
	species VARCHAR(255),
	dateCreated DATETIME DEFAULT CURRENT_TIMESTAMP,
	datePlanted DATE,
	numberOfTrees INT,
	imageUrl VARCHAR(255),
	location VARCHAR(255),
	longitude DECIMAL(10, 6),
	latitude DECIMAL(10, 6),
	lastUpdated DATETIME ON UPDATE CURRENT_TIMESTAMP,
	isConfirmed BOOLEAN DEFAULT false,
	isRevoked BOOLEAN DEFAULT false,
	FOREIGN KEY (userId) REFERENCES User(userId) ON DELETE CASCADE
);

-- Create the RegisteredEvent table
CREATE TABLE IF NOT EXISTS RegisteredEvent (
	registeredEventId INT AUTO_INCREMENT PRIMARY KEY,
	userId INT,
	eventId INT,
	isCancelled BOOLEAN DEFAULT false,
	isAttended BOOLEAN DEFAULT false,
	dateCreated DATETIME DEFAULT CURRENT_TIMESTAMP,
	lastUpdated DATETIME ON UPDATE CURRENT_TIMESTAMP,
	FOREIGN KEY (userId) REFERENCES User(userId) ON DELETE CASCADE,
	FOREIGN KEY (eventId) REFERENCES Event(eventId) ON DELETE CASCADE
);
