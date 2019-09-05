from app import db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    # User ID
    uid = db.Column(db.Integer, primary_key=True)
    # Company ID
    coid = db.Column(db.Integer, nullable=True)

    # Access tokens
    twitter_access_token = db.Column(db.String(64), nullable=True)
    twitter_access_token_secret = db.Column(db.String(64), nullable=True)
    facebook_access_token = db.Column(db.String(64), nullable=True)
    facebook_access_token_secret = db.Column(db.String(64), nullable=True)
    insta_access_token = db.Column(db.String(64), nullable=True)
    insta_access_token_secret = db.Column(db.String(64), nullable=True)
    youtube_access_token = db.Column(db.String(64), nullable=True)
    youtube_access_token_secret = db.Column(db.String(64), nullable=True)
    

@login.user_loader
def load_user(id):
    return User.query.get(int(id))
