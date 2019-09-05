from flask import Flask, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from oauth import OAuthSignIn
from app import app, db
import os, sys
from app.models import User
import tweepy
from TwitterAPI import TwitterAPI


@app.route('/')
def index():
    # Store the user id and the company id, create an account with those two pieces of info stored
    # Then just update the user info as required
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
        if provider is 'twitter':
            # define access tokens in user accounts, based on which website they're querying
            user = User(social_id=social_id, nickname=username, email=email, twitter_access_token=access_token, twitter_access_token_secret = access_token_secret)
        elif provider is 'google':
            pass
        elif provider is 'facebook':
            pass
        elif provider is 'instagram':
            pass
        db.session.add(user)
        db.session.commit()
    login_user(user, True)
    return redirect(url_for('index'))

@login_required
@app.route('/upload/twitter')
def send_twitter():
    error = False
    problem = "Unknown"
    creds = app.config['OAUTH_CREDENTIALS']['twitter']

    twitter = TwitterAPI(
        creds['id'], 
        creds['secret'], 
        current_user.twitter_access_token, 
        current_user.twitter_access_token_secret
    )    

    # TODO: CHANGE THIS TO BE IMPLICIT
    VIDEO_FILENAME = 'N:/test.mp4'

    bytes_sent = 0
    total_bytes = os.path.getsize(VIDEO_FILENAME)
    file = open(VIDEO_FILENAME, 'rb')

    def check_status(r):
        if r.status_code < 200 or r.status_code > 299:
            print(r.status_code)
            print(r.text)
            if r.status_code == 400:
                print("Video Length is too long")
                print(type(r.text))
                problem = r.text
                error = True
                return
            sys.exit(0)

    # initialize media upload and get a media reference ID in the response
    r = twitter.request('media/upload', {'command':'INIT', 'media_type':'video/mp4', 'total_bytes':total_bytes})
    check_status(r)

    media_id = r.json()['media_id']
    segment_id = 0

    # start chucked upload
    while bytes_sent < total_bytes:
        chunk = file.read(4*1024*1024)
    
        # upload chunk of byets (5mb max)
        r = twitter.request('media/upload', {'command':'APPEND', 'media_id':media_id, 'segment_index':segment_id}, {'media':chunk})
        check_status(r)
        segment_id = segment_id + 1
        bytes_sent = file.tell()
        print('[' + str(total_bytes) + ']', str(bytes_sent))

    # finalize the upload
    r = twitter.request('media/upload', {'command':'FINALIZE', 'media_id':media_id})
    check_status(r)

    # post Tweet with media ID from previous request
    # TODO: SET STATUS AS USER INPUT
    stat = 'Video uploaded from python script. #python @RuairiMacGuinn'
    r = twitter.request('statuses/update', {'status': stat, 'media_ids':media_id})
    check_status(r)
    # Change this to redirect to a success page with the same data
    if error:
        return "Video not uploaded successfully. Here's why: {}".format(problem)
    else:
        return "Video Successfully uploaded!"

@login_required
@app.route('/upload/facebook')
def send_facebook():
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
 
    api = tweepy.API(auth)
    api.update_status('Updating using OAuth authentication via Tweepy!')


@login_required
@app.route('/upload/youtube')
def send_youtube():
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
    auth.set_access_token(User.twitter_access_token, User.twitter_access_token_secret)

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