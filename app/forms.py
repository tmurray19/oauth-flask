from flask_wtf import FlaskForm
from wtforms import StringField, RadioField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired

class YoutubeForm(FlaskForm):
    title = StringField('Video Title', validators=[DataRequired()])
    description = TextAreaField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class TwitterForm(FlaskForm):
    status_body = StringField('Tweet', validators=[DataRequired()])
    submit = SubmitField('Post video to twitter')