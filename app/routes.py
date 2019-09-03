from flask import Flask, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from oauth import OAuthSignIn
from app import app, db
from app.models import User
import tweepy


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    social_id, username, email, access_token, access_token_secret = oauth.callback()
    if social_id is None:
        flash('Authentication failed.')
        return redirect(url_for('index'))
    user = User.query.filter_by(social_id=social_id).first()
    if not user:
        user = User(social_id=social_id, nickname=username, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user, True)
    return redirect(url_for('index'))

@login_required
@app.route('/upload/twitter')
def send_twitter():
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
    auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)

    api = tweepy.API(auth)
    api.update_status('Updating using OAuth authentication via Tweepy!')

@login_required
@app.route('/upload/facebook')
def send_facebook():
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
    auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)

    api = tweepy.API(auth)
    api.update_status('Updating using OAuth authentication via Tweepy!')

@login_required
@app.route('/upload/youtube')
def send_youtube():
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
    auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)

    api = tweepy.API(auth)
    api.update_status('Updating using OAuth authentication via Tweepy!')

@login_required
@app.route('/upload/instagram')
def send_insta():
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
    auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)

    api = tweepy.API(auth)
    api.update_status('Updating using OAuth authentication via Tweepy!')