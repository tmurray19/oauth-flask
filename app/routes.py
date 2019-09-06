from flask import Flask, redirect, url_for, render_template, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from oauth import OAuthSignIn
from app import app, db
import os, sys
from app.models import User
from TwitterAPI import TwitterAPI
import random, time
from .forms import TwitterForm

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow


@app.route('/')
def index():
    if current_user.is_anonymous:
        return redirect("http://dev.squarev.mobi")
    return render_template('index.html')

# LANDING PAGES
@app.route('/connect/COID=<int:companyid>/UID=<int:uid>')
def init_connect(uid, companyid):
    # Store the user id and the company id, create an account with those two pieces of info stored
    # Then just update the user info as required
    if current_user.is_anonymous:
        user = User.query.filter_by(uid=uid).first()
        if not user:
            user = User(uid=uid, coid=companyid)
            db.session.add(user)
            db.session.commit()
        login_user(user, True)
    return render_template('index.html')

@app.route('/publish/COID=<int:companyid>/UID=<int:uid>/PID=<int:projectid>')
def publish_land(uid, companyid, projectid):
    if current_user.is_anonymous:
        user = User.query.filter_by(uid=uid).first()
        if not user:
            user = User(uid=uid, coid=companyid)
            db.session.add(user)
            db.session.commit()
        login_user(user, True)
    return render_template('publish.html', proj_id=projectid)

# AUTHORIZATION SERVICES
@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if provider == 'facebook' or provider == "instagram":
        print("We should be here if anything other than twitter is clicked.")
        return render_template('error.html')
    if provider == 'google':
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            app.config['CLIENT_SECRETS_FILE'], 
            scopes=app.config['SCOPES']
        )

        flow.redirect_uri = url_for('oauth2callback', _external=True)

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )

        # Store the state so the callback can verify the auth server response.
        session['state'] = state

        return redirect(authorization_url)
    else:
        oauth = OAuthSignIn.get_provider(provider)
        return oauth.authorize()

# For youtube
@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        app.config['CLIENT_SECRETS_FILE'], 
        scopes=app.config['SCOPES'], 
        state=state
    )
    
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response) 
    credentials = flow.credentials

    print(credentials)
    print(credentials_to_dict(credentials))

    # TODO: WRITE THIS INFORMATION TO THE USER ACCOUNT
    current_user.youtube_credentials = credentials_to_dict(credentials)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/callback/<provider>')
def oauth_callback(provider):
    oauth = OAuthSignIn.get_provider(provider)
    social_id, access_token, access_token_secret = oauth.callback()
    print(social_id)  
    if social_id is None:
        flash('Authentication failed.')
        return redirect(url_for('index'))
    print(provider=='twitter')
    if provider == 'twitter':
        current_user.twitter_access_token = access_token
        current_user.twitter_access_token_secret = access_token_secret
        db.session.commit()
    return redirect(url_for('index'))

# UI Upload helpers
@app.route('/publish/twitter/<int:proj_id>')
def publish_twitter(proj_id):
    return render_template('twitter.html', proj_id=proj_id)

# API Upload functions
@login_required
@app.route('/upload/twitter/<int:proj_id>', methods=['POST'])
def send_twitter(proj_id):
    stat = 'Video uploaded from python script. #python @RuairiMacGuinn'
    stat = request.form['tweet_body']
    twitter_upload_error=False
    problem = "No error specified"
    creds = app.config['OAUTH_CREDENTIALS']['twitter']

    twitter = TwitterAPI(
        creds['id'], 
        creds['secret'], 
        current_user.twitter_access_token, 
        current_user.twitter_access_token_secret
    )    

    # TODO: CHANGE THIS TO BE IMPLICIT
    VIDEO_FILENAME = '/mnt/csae48d5df47deax41bcxbaa/videos/vid.mp4'
    VIDEO_FILENAME = os.path.join('/mnt/csae48d5df47deax41bcxbaa/videos/', str(proj_id), str(proj_id)+'_edited.mp4')

    bytes_sent = 0
    total_bytes = os.path.getsize(VIDEO_FILENAME)
    file = open(VIDEO_FILENAME, 'rb')

    def check_status(r):
        if r.status_code < 200 or r.status_code > 299:
            print(r.status_code)
            print(r.text)
            problem = r.text
            twitter_upload_error = True
            print("Problem occured")
            twitter_status = "Video not uploaded successfully. Here's why: {}".format(problem)
            return twitter_status

    # initialize media upload and get a media reference ID in the response
    r = twitter.request('media/upload', {'command':'INIT', 'media_type':'video/mp4', 'total_bytes':total_bytes})
    check_status(r)

    media_id = r.json()['media_id']
    segment_id = 0

    # start chucked upload
    while bytes_sent < total_bytes:
        twitter_status = "File is uploading"
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
    r = twitter.request('statuses/update', {'status': stat, 'media_ids':media_id})
    check_status(r)
    # Change this to redirect to a success page with the same data
    twitter_status = "Uploaded successfully"
    return twitter_status

@login_required
@app.route('/upload/facebook')
def send_facebook():
    return render_template('error.html')
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    #auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
 
    #api = tweepy.API(auth)
    api.update_status('Updating using OAuth authentication via Tweepy!')


@login_required
@app.route('/upload/youtube')
def send_youtube():
    credentials = google.oauth2.credentials.Credentials(**current_user.youtube_credentials)
    youtube = build(
        "youtube", 
        "v3",
        credentials=credentials
    )

    body=dict(
        snippet=dict(
            title="TEst",
            description="options.description",
            tags="tags",
            categoryId="22"
        ),
        status=dict(
            privacyStatus="public"
        )
    )

    # TODO: Implicity file name
    insert_request = youtube.videos().insert(
      part=",".join(list(body.keys())),
      body=body,
      media_body=MediaFileUpload('/mnt/csae48d5df47deax41bcxbaa/videos/vid.mp4', chunksize=-1, resumable=True)
    )

    resumable_upload(insert_request)
    
    return "Uploaded video successfully!"

@login_required
@app.route('/upload/instagram')
def send_insta():

    return render_template('error.html')
    creds = app.config['OAUTH_CREDENTIALS']['twitter']
    #auth = tweepy.OAuthHandler(creds['id'], creds['secret'])
    auth.set_access_token(ACCESS_KEY, ACCESS_SECRET)

    #api = tweepy.API(auth)
    api.update_status('Updating using OAuth authentication via Tweepy!')


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


def resumable_upload(insert_request):
    response = None
    error = None
    retry = 0
    while response is None:
        try:
            print("Uploading file...")
            status, response = insert_request.next_chunk()
            if 'id' in response:
                print("Video id '%s' was successfully uploaded." % response['id'])
            else:
                exit("The upload failed with an unexpected response: %s" % response)
        except HttpError as e:
            if e.resp.status in app.config['RETRIABLE_STATUS_CODES']:
                error = "A retriable HTTP error %d occurred:\n%s" % (e.resp.status, e.content)
            else:
                raise
        except app.config['RETRIABLE_EXCEPTIONS'] as e:
            error = "A retriable error occurred: %s" % e
        
        if error is not None:
            print(error)
            retry += 1
        if retry > app.config['MAX_RETRIES']:
            exit("No longer attempting to retry.")
        
        max_sleep = 2 ** retry
        sleep_seconds = random.random() * max_sleep
        print("Sleeping %f seconds and then retrying..." % sleep_seconds)
        time.sleep(sleep_seconds)


