from app import db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)

    # User ID
    uid = db.Column(db.Integer, nullable=False)
    # Company ID
    coid = db.Column(db.Integer, nullable=True)

    # Social ID (May be defunct)
    social_id = db.Column(db.String(64), nullable=True)

    # Access tokens
    twitter_access_token = db.Column(db.String(64), nullable=True)
    twitter_access_token_secret = db.Column(db.String(64), nullable=True)
    facebook_access_token = db.Column(db.String(64), nullable=True)
    facebook_access_token_secret = db.Column(db.String(64), nullable=True)
    insta_access_token = db.Column(db.String(64), nullable=True)
    insta_access_token_secret = db.Column(db.String(64), nullable=True)
    #youtube_access_token = db.Column(db.String(64), nullable=True)
    #youtube_access_token_secret = db.Column(db.String(64), nullable=True)
    youtube_credentials = db.Column(db.PickleType, nullable=True)
    linkedin_access_token = db.Column(db.String(64), nullable=True)
    linkedin_access_token_secret = db.Column(db.String(64), nullable=True)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

#https://127.0.0.1:5000/connect/COID=45/UID=45
#https://127.0.0.1:5000/publish/COID=512/UID=12/PID=1794