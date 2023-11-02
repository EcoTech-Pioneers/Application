from flask_wtf import FlaskForm
from wtforms import StringField, DateField, IntegerField, FileField, TextAreaField, DateTimeField
from wtforms.fields.html5 import DateTimeLocalField
from wtforms.validators import DataRequired, Length

class AddRecordForm(FlaskForm):
    species = StringField('Species', [DataRequired(), Length(max=255)])
    datePlanted = DateField('Date Planted', [DataRequired()], format='%Y-%m-%d')
    numberOfTrees = IntegerField('Number of Trees', [DataRequired()])
    imageUrl = FileField('Upload Images', [Length(max=255)])
    location = StringField('Location', [DataRequired(), Length(max=255)])


class CreateEventForm(FlaskForm):
    title = StringField('Event Title', [DataRequired(), Length(max=255)])
    description = TextAreaField('Event Description', [DataRequired()])
    imageUrl = FileField('Upload Image', [Length(max=255)])
    startDateTime = DateTimeLocalField('Start Date and Time', [DataRequired()])
    endDateTime = DateTimeLocalField('End Date and Time', [DataRequired()])
    venue = StringField('Venue', [DataRequired(), Length(max=255)])
    organizer = StringField('Organizer', [Length(max=128)])
