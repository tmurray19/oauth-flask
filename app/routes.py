from flask import Flask, redirect, url_for, render_template, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from oauth import OAuthSignIn
from app import app, db
import os, sys, json, requests
from app.models import User
import random, time
from requests_oauthlib import OAuth1
import logging
from datetime import datetime

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import googleapiclient.errors

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow


# We don't want anonymous users going here
@app.route('/')
def index():
    if current_user.is_anonymous:
        logging.debug("Request made without logging in, sending back to editor")
        return redirect("http://beta.videosherpa.com")
    return render_template('index.html')

# This is our request page for the user, it creates an accosunt under the uid and sends them to the auth page
@app.route('/connect/COID=<int:companyid>/UID=<int:userid>')
def init_connect(userid, companyid):
    # Logout user
    logout_user()
    # If the user doesn't exist, create an account and store it in the database
    if current_user.is_anonymous:
        user = User.query.filter_by(coid=companyid).first()
        logging.debug("Logging user in with company id {}".format(companyid))
        print("Logging user in with company id {}".format(companyid))
        if not user:
            logging.debug("User doesn't exist, creating account in database")
            print("User doesn't exist, creating account in database")
            user = User(uid=userid, coid=companyid)
            db.session.add(user)
            db.session.commit()
            logging.debug("User successfully created")
        # Log the user in
        login_user(user, True)
    # Send them to the landing page, where they authenticate other services
    logging.debug("Current User: {}".format(current_user))
    return render_template('index.html')

# This shows the user the upload pages for the accounts they have unlocked
@app.route('/publish/COID=<int:companyid>/UID=<int:uid>/PID=<int:projectid>')
def publish_land(uid, companyid, projectid):
    logout_user()
    if current_user.is_anonymous:
        user = User.query.filter_by(coid=companyid).first()
        # Tells user to authenticate if their account doesn't exist
        if not user:
            logging.error("User with coid={} and uid={} doesn't exist in database".format(companyid, uid))
            return render_template('invalid.html')
        login_user(user, True)
    
    json_data = get_metadata(projectid)

    upload_status = get_upload_status(projectid)

    return render_template('publish.html', data=json_data, status=upload_status)

# AUTHORIZATION SERVICES
@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if provider == "instagram":
        logging.debug("An unavailable social media account has been provided.")
        return render_template('error.html')
    # Google needs to be handled separately
    if provider == 'google':
        # Create an OAuth flow to the google servers using the info in the config
        logging.debug("Beginning dance for google OAuth")
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            app.config['CLIENT_SECRETS_FILE'],
            scopes=app.config['SCOPES']
        )

        logging.debug("Google OAuth flow connection established")

        # Get the URI to redirect the user back to the website once auth'd on google services
        flow.redirect_uri = url_for('oauth2callback', _external=True)

        # Get link to direct user to google
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )

        # Store the state so the callback can verify the auth server response.
        session['state'] = state
        
        # Return the google auth url to user
        return redirect(authorization_url)
    else:
        logging.debug("Facebook or Twitter requested, beginning relevant OAuth dance")
        oauth = OAuthSignIn.get_provider(provider)
        return oauth.authorize()

# For youtube
@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = session['state']
        logging.debug("Reading google credentials to authenticate user")
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            app.config['CLIENT_SECRETS_FILE'], 
            scopes=app.config['SCOPES'], 
            state=state
        )
        
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response) 
        credentials = flow.credentials

        youtube = googleapiclient.discovery.build(
            app.config['YOUTUBE_API_SERVICE_NAME'], app.config['YOUTUBE_API_VERSION'], credentials=credentials)

        logging.debug("Getting Youtube ID")
        channel_id_getter = youtube.channels().list(part="id", mine=True)

        response = channel_id_getter.execute()
        channel_id = response['items'][0]['id']


        channel_name_getter = youtube.channels().list(part="snippet", id=channel_id)
        response = channel_name_getter.execute()
        channel_name = response['items'][0]['snippet']['title']

        logging.debug("Writing user credentials to database for user with coid={} and uid={}".format(current_user.coid, current_user.uid))
        current_user.youtube_credentials = credentials_to_dict(credentials)
        current_user.youtube_id = channel_name
        db.session.commit()
        logging.debug("User successfully authenticated")
        return redirect(url_for('index'))
    except:
        return render_template('error.html')

@app.route('/callback/<provider>')
def oauth_callback(provider):
    try:
        oauth = OAuthSignIn.get_provider(provider)

        social_id, access_token, access_token_secret, fb_page_id, username = oauth.callback()
        if social_id is None:
            logging.debug("Authentication failed")
            flash('Authentication failed.')
            return redirect(url_for('index'))
        if provider == 'twitter':
            logging.debug("Writing twitter credentials to account for user with coid={} and uid={}".format(current_user.coid, current_user.uid))
            
            current_user.twitter_id = username
            current_user.twitter_access_token = access_token
            current_user.twitter_access_token_secret = access_token_secret
            
            db.session.commit()
        elif provider == 'facebook':

            logging.debug("user with coid={} and uid={} first page access token is being written to the database".format(current_user.coid, current_user.uid))
            
            current_user.facebook_id = username
            current_user.facebook_access_token_secret = access_token_secret
            current_user.facebook_access_token = fb_page_id

            db.session.commit()
        return redirect(url_for('index'))
    except:
        return render_template('error.html')

# UI Upload helpers
@login_required
@app.route('/publish/twitter/<int:proj_id>')
def publish_twitter(proj_id):

    # Open JSON data to read metadata
    json_data = get_metadata(proj_id)

    logging.debug("User with coid={} and uid={} has made a request for Twitter upload".format(current_user.coid, current_user.uid))
    return render_template('twitter.html', data=json_data)

@login_required
@app.route('/publish/youtube/<int:proj_id>')
def publish_youtube(proj_id):

    # Open JSON data to read metadata
    json_data = get_metadata(proj_id)

    logging.debug("User with coid={} and uid={} has made a request for Youtube upload".format(current_user.coid, current_user.uid))
    return render_template('google.html', data=json_data)

@login_required
@app.route('/publish/facebook/<int:proj_id>')
def publish_facebook(proj_id):    
    
    # Open JSON data to read metadata
    json_data = get_metadata(proj_id)

    logging.debug("User with coid={} and uid={} has made a request for Facebook upload".format(current_user.coid, current_user.uid))
    return render_template('facebook.html', data=json_data)

# API Upload functions
@login_required
@app.route('/upload/twitter/<int:proj_id>', methods=['POST'])
def send_twitter(proj_id):
    # Twitter status - This is the tweet
    stat = request.form['twitter_body']

    twitter_json = {
        'social_media': 'twitter',
        'proj_id': proj_id,
        'twitter_body': stat,
        'coid': current_user.coid,
        'uid': current_user.uid,
        'access_token': current_user.twitter_access_token,
        'access_token_secret': current_user.twitter_access_token_secret,
        'upload_status': 0,
        'status': False,
        'dateRequested': datetime.now().strftime("%d-%b-%Y (%H:%M:%S)")
    }

    logging.debug("Writing upload status to file")
    with open(
        os.path.join(
            app.config['BASE_DIR'],
            app.config['UPLOAD_QUEUE'],
            str(proj_id) + "_" + twitter_json['social_media'] + "_upload_status.json"
        ), 'w'
    ) as json_write:
        json.dump(twitter_json, json_write)

    return render_template('requested.html', proj_id=proj_id)


@login_required
@app.route('/upload/youtube/<int:proj_id>', methods=['POST'])
def send_youtube(proj_id):

    youtube_json = {
        'social_media': 'youtube',
        'proj_id': proj_id,
        'yt_title': request.form['yt_title'],
        'yt_desc': request.form['yt_desc'],
        'yt_tags': request.form['yt_tags'],
        'yt_privacy': request.form['privacy'],
        'coid': current_user.coid,
        'uid': current_user.uid,
        'youtube_credentials': current_user.youtube_credentials,
        'upload_status': 0,
        'status': False,
        'dateRequested': datetime.now().strftime("%d-%b-%Y (%H:%M:%S)")
    }

    logging.debug("Writing upload status to file")
    with open(
        os.path.join(
            app.config['BASE_DIR'],
            app.config['UPLOAD_QUEUE'],
            str(proj_id) + "_" + youtube_json['social_media'] + "_upload_status.json"
        ), 'w'
    ) as json_write:
        json.dump(youtube_json, json_write)
    
        
    return render_template('requested.html', proj_id=proj_id)



@login_required
@app.route('/upload/facebook/<int:proj_id>', methods=['POST'])
def send_facebook(proj_id):

    facebook_json = {
        'social_media': 'facebook',
        'proj_id': proj_id,
        'facebook_title': request.form['facebook_title'],
        'facebook_body': request.form['facebook_body'],
        'coid': current_user.coid,
        'uid': current_user.uid,
        'access_token': current_user.facebook_access_token,
        'access_token_secret': current_user.facebook_access_token_secret,
        'upload_status': 0,
        'status': False,
        'dateRequested': datetime.now().strftime("%d-%b-%Y (%H:%M:%S)")
    }

    with open(
        os.path.join(
            app.config['BASE_DIR'],
            app.config['UPLOAD_QUEUE'],
            str(proj_id) + "_" + facebook_json['social_media'] + "_upload_status.json"
        ), 'w'
    ) as json_write:
        json.dump(facebook_json, json_write)
    
    return render_template('requested.html', proj_id=proj_id)


@login_required
@app.route('/upload/instagram')
def send_insta():
    pass


# Utility functions
def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


def get_metadata(proj_id):
    base_dir = os.path.join(app.config['BASE_DIR'], app.config['VIDS_LOCATION'], str(proj_id))
    file_location = os.path.join(base_dir, 'FinalSubclipJson.json')

    json_data = json.load(open(file_location, 'r'))

    try:
        vid_icon = next(iter(json_data['CutAwayFootage']))
        vid_icon = json_data['CutAwayFootage'][vid_icon]['Meta']['name'] + ".jpg"
    except StopIteration:
        vid_icon = next(iter(json_data['InterviewFootage']))
        vid_icon = json_data['InterviewFootage'][vid_icon]['Meta']['name'] + ".jpg"
    except:
        logging.error("Unknown error in creation of metadata for '{}'".format(proj_id))
        logging.exception('')
        return None

    vid_icon = os.path.join(base_dir, vid_icon)

    data = {
        'proj_id': str(proj_id),
        'vid_name': json_data['Name'],
        'vid_icon': vid_icon,
    }

    print(data)

    return data


def get_upload_status(proj_id):
    # Checks upload status folder for upload files
    # If they exist, checks status
    # If status is true, removes upload button option for folder
    # Else says an error occured, contact admins

    twitter_status = None
    try:
        twitter_file = os.path.join(
            app.config['BASE_DIR'],
            app.config['UPLOAD_QUEUE'],
            str(proj_id) + "_twitter_upload_status.json"
        )
        json_file = open(twitter_file, 'r')
        json_data = json.load(json_file)
        twitter_status = json_data['upload_status']

        current_time = time.time()

        upload_timestamp = json_data['dateRequested']

        if current_time - upload_timestamp > 300:
            twitter_status = 5

    except:
        pass

    facebook_status = None
    try:
        facebook_file = os.path.join(
            app.config['BASE_DIR'],
            app.config['UPLOAD_QUEUE'],
            str(proj_id) + "_facebook_upload_status.json"
        )
        json_file = open(facebook_file, 'r')
        json_data = json.load(json_file)
        facebook_status = json_data['upload_status']

        current_time = time.time()

        upload_timestamp = json_data['dateRequested']

        if current_time - upload_timestamp > 300:
            facebook_status = 5

    except:
        pass

    youtube_status = None
    try:
        youtube_file = os.path.join(
            app.config['BASE_DIR'],
            app.config['UPLOAD_QUEUE'],
            str(proj_id) + "_youtube_upload_status.json"
        )
        json_file = open(youtube_file, 'r')
        json_data = json.load(json_file)
        youtube_status = json_data['upload_status']

        current_time = time.time()

        upload_timestamp = json_data['dateRequested']

        if current_time - upload_timestamp > 300:
            youtube_status = 5

    except:
        pass

    return {
        "twitter": twitter_status, 
        "facebook": facebook_status, 
        "youtube": youtube_status
    }