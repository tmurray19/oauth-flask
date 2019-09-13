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

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

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
        return redirect("http://dev.squarev.mobi")
    return render_template('index.html')

# This is our request page for the user, it creates an account under the uid and sends them to the auth page
@app.route('/connect/COID=<int:companyid>/UID=<int:uid>')
def init_connect(uid, companyid):
    # If the user doesn't exist, create an account and store it in the database
    if current_user.is_anonymous:
        user = User.query.filter_by(coid=companyid).first()
        logging.debug("Logging user in with company id {}".format(companyid))
        if not user:
            logging.debug("User doesn't exist, creating account in database")
            user = User(uid=uid, coid=companyid)
            db.session.add(user)
            db.session.commit()
            logging.debug("User successfully created")
        # Log the user in
        login_user(user, True)
    # Send them to the landing page, where they authenticate other services
    return render_template('index.html')

# This shows the user the upload pages for the accounts they have unlocked
@app.route('/publish/COID=<int:companyid>/UID=<int:uid>/PID=<int:projectid>')
def publish_land(uid, companyid, projectid):
    if current_user.is_anonymous:
        user = User.query.filter_by(coid=companyid).first()
        # Tells user to authenticate if their account doesn't exist
        if not user:
            logging.error("User with coid={} and uid={} doesn't exist in database".format(companyid, uid))
            return render_template('invalid.html')
        login_user(user, True)
    return render_template('publish.html', proj_id=projectid)

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


    logging.debug("Writing user credentials to database for user with coid={} and uid={}".format(current_user.coid, current_user.uid))
    current_user.youtube_credentials = credentials_to_dict(credentials)
    db.session.commit()
    logging.debug("User successfully authenticated")
    return redirect(url_for('index'))

@app.route('/callback/<provider>')
def oauth_callback(provider):
    oauth = OAuthSignIn.get_provider(provider)
    # TODO: Better variable name
    # Dummy is FB page id
    social_id, access_token, access_token_secret, fb_page_id = oauth.callback()
    if social_id is None:
        logging.debug("Authentication failed")
        flash('Authentication failed.')
        return redirect(url_for('index'))
    if provider == 'twitter':
        logging.debug("Writing twitter credentials to account for user with coid={} and uid={}".format(current_user.coid, current_user.uid))
        current_user.twitter_access_token = access_token
        current_user.twitter_access_token_secret = access_token_secret
        db.session.commit()
    elif provider == 'facebook':

        logging.debug("user with coid={} and uid={} first page access token is being written to the database".format(current_user.coid, current_user.uid))

        current_user.facebook_access_token_secret = access_token_secret

        current_user.facebook_access_token = fb_page_id
        db.session.commit()
    return redirect(url_for('index'))

# UI Upload helpers
@login_required
@app.route('/publish/twitter/<int:proj_id>')
def publish_twitter(proj_id):
    logging.debug("User with coid={} and uid={} has made a request for Twitter upload".format(current_user.coid, current_user.uid))
    return render_template('twitter.html', proj_id=proj_id)

@login_required
@app.route('/publish/youtube/<int:proj_id>')
def publish_youtube(proj_id):    
    logging.debug("User with coid={} and uid={} has made a request for Twitter upload".format(current_user.coid, current_user.uid))
    return render_template('google.html', proj_id=proj_id)

@login_required
@app.route('/publish/facebook/<int:proj_id>')
def publish_facebook(proj_id):
    logging.debug("User with coid={} and uid={} has made a request for Twitter upload".format(current_user.coid, current_user.uid))
    return render_template('facebook.html', proj_id=proj_id)

# API Upload functions
@login_required
@app.route('/upload/twitter/<int:proj_id>', methods=['POST'])
def send_twitter(proj_id):
    # Twitter status
    stat = request.form['tweet_body']

    creds = app.config['OAUTH_CREDENTIALS']['twitter']

    # File location
    VIDEO_FILENAME = os.path.join('/mnt/csae48d5df47deax41bcxbaa/videos/', str(proj_id), str(proj_id)+'_edited.mp4')

    logging.debug("Project {} for upload to Twitter".format(proj_id))
    logging.debug("Request made by user with coid={} and uid={}".format(current_user.coid, current_user.uid))
    logging.debug("Tweet body for {} is {} ".format(proj_id, stat))

    # Create OAuth1 flow
    oauth_connection = OAuth1(
        creds['id'],
        creds['secret'],
        current_user.twitter_access_token,
        current_user.twitter_access_token_secret
    )

    # Open file for uploading
    bytes_sent = 0
    total_bytes = os.path.getsize(VIDEO_FILENAME)
    file = open(VIDEO_FILENAME, 'rb')

 
    # Initialise request
    logging.debug("Initialising request for {}".format(proj_id))
    request_data = {
        'command': 'INIT',
        'media_type': 'video/mp4',
        'total_bytes': total_bytes,
        'media_category': 'tweet_video'
    }

    req = requests.post(url=app.config['MEDIA_ENDPOINT_URL'], data=request_data, auth=oauth_connection)
    media_id = req.json()['media_id']
    
    segment_id = 0
    bytes_sent = 0

    # Video needs to be uploaded in chunks
    while bytes_sent < total_bytes:
        chunk = file.read(4*1024*1024)
        
        logging.debug("APPEND FOR {}".format(proj_id))
        
        request_data = {
            'command': 'APPEND',
            'media_id': media_id,
            'segment_index': segment_id
        }

        files = {
            'media':chunk
        }
        
        req = requests.post(url=app.config['MEDIA_ENDPOINT_URL'], data=request_data, files=files, auth=oauth_connection)

        # If status code isn't in 200 range, something has gone wrong
        if req.status_code < 200 or req.status_code > 299:
            logging.error("Error occured in uploading of file {}:\n Status Code: {} \n Details: {}".format(proj_id, req.status_code, req.text))
            sys.exit(0)

        segment_id = segment_id + 1
        bytes_sent = file.tell()

        logging.debug('{} of {} bytes uploaded for {}'.format(str(bytes_sent), str(total_bytes), proj_id))

    logging.debug('Upload chunks complete for {}.'.format(proj_id))

    logging.debug("FINALIZE")

    request_data = {
      'command': 'FINALIZE',
      'media_id': media_id
    }

    req = requests.post(url=app.config['MEDIA_ENDPOINT_URL'], data=request_data, auth=oauth_connection)
    logging.debug(req.json())

    processing_info = req.json().get('processing_info', None)
    check_status(processing_info, media_id, oauth_connection, proj_id)

    request_data = {
      'status': stat,
      'media_ids': media_id
    }

    req = requests.post(url=app.config['POST_TWEET_URL'], data=request_data, auth=oauth_connection)
    logging.debug(req.json())

    twitter_status = "Uploaded successfully"
    logging.debug("File {} uploaded successfully".format(proj_id))
    return twitter_status


@login_required
@app.route('/upload/youtube/<int:proj_id>', methods=['POST'])
def send_youtube(proj_id):
    credentials = google.oauth2.credentials.Credentials(**current_user.youtube_credentials)
    
    VIDEO_FILENAME = os.path.join('/mnt/csae48d5df47deax41bcxbaa/videos/', str(proj_id), str(proj_id)+'_edited.mp4')
    
    logging.debug("Project {} for upload to Youtube".format(proj_id))
    logging.debug("Request made by user with coid={} and uid={}".format(current_user.coid, current_user.uid))

    youtube = build(
        "youtube", 
        "v3",
        credentials=credentials
    )

    body=dict(
        snippet=dict(
            title=request.form['title'],
            description=request.form['yt_desc'],
            tags=request.form['tags'],
            categoryId="22"
        ),
        status=dict(
            privacyStatus=request.form['privacy']
        )
    )

    logging.debug("Request data is {}, creating insert request for {}".format(body, proj_id))

    # TODO: Implicity file name
    insert_request = youtube.videos().insert(
      part=",".join(list(body.keys())),
      body=body,
      media_body=MediaFileUpload(VIDEO_FILENAME, chunksize=-1, resumable=True)
    )

    logging.debug("Calling upload function for {}...".format(proj_id))
    resumable_upload(insert_request, proj_id)
    
    return "Uploaded video successfully!"


@login_required
@app.route('/upload/facebook/<int:proj_id>', methods=['POST'])
def send_facebook(proj_id):
    url='https://graph-video.facebook.com/{}/videos?access_token={}'.format(
        current_user.facebook_access_token,
        current_user.facebook_access_token_secret
    )
    name = request.form['facebook_title']
    desc = request.form['facebook_body']
    VIDEO_FILENAME = os.path.join('/mnt/csae48d5df47deax41bcxbaa/videos/', str(proj_id), str(proj_id)+'_edited.mp4')
    VIDEO_LOC = os.path.join('N:/project/videos/', str(proj_id), str(proj_id)+'_edited.mp4')
    VIDEO_FILENAME = str(proj_id) + "_edited.mp4"
    
    payload = {
        'title': name,
        'description': desc,
    }
    files = {
        'source': (
            VIDEO_FILENAME, 
            open(VIDEO_LOC, 'rb'), 
            'video/mp4'
            )
        }

    logging.debug("Project {} for upload to Facebook".format(proj_id))
    logging.debug("Request made by user with coid={} and uid={}".format(current_user.coid, current_user.uid))

    flag = requests.post(url, data=payload, files=files).text
    logging.debug(flag)
    fb_res = json.loads(flag)
    if not fb_res["error"]:
        logging.debug("Project {} uploaded successfully".format(proj_id))
        return "Video successfully uploaded to Facebook"
    else:
        logging.debug("Error occured in upload of {}\n{}".format(proj_id, fb_res))
        return "There was an error during upload. Please try again or contact the Video Sherpa administrators."

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


def resumable_upload(insert_request, proj_id):
    response = None
    error = None
    retry = 0
    while response is None:
        try:
            logging.debug("Uploading file for {}".format(proj_id))
            status, response = insert_request.next_chunk()
            if 'id' in response:
                logging.debug("Video id '{}' was successfully uploaded.".format(response['id']))
            else:                
                logging.error("The upload for file {} failed with an unexpected response: {}".format(proj_id, response))       
                exit("The upload failed with an unexpected response: %s" % response)                

        except HttpError as e:
            if e.resp.status in app.config['RETRIABLE_STATUS_CODES']:
                error = "A retriable HTTP error {} occurred for {}:\n Content: {}".format(e.resp.status, proj_id, e.content)
            else:
                raise
        except app.config['RETRIABLE_EXCEPTIONS'] as e:
            error = "A retriable error occurred for {}: {}".format(proj_id, e)
        
        if error is not None:
            logging.error(error)
            retry += 1
        if retry > app.config['MAX_RETRIES']:
            logging.error("No longer attempting to retry for {}.".format(proj_id))
            exit("No longer attempting to retry.")
        
        max_sleep = 2 ** retry
        sleep_seconds = random.random() * max_sleep
        logging.debug("Sleeping {} seconds and then retrying for {}...".format(sleep_seconds, proj_id))
        time.sleep(sleep_seconds)


def check_status(processing_info, media_id, oauth_connection, proj_id):
    '''
    Checks video processing status
    '''
    if processing_info is None:
      return

    state = processing_info['state']

    logging.debug('Media processing status for {} is {}'.format(proj_id, state))

    if state == u'succeeded':
      return

    if state == u'failed':
      sys.exit(0)

    check_after_secs = processing_info['check_after_secs']
    
    logging.debug('Checking after {} seconds for {}'.format(str(check_after_secs), proj_id))
    time.sleep(check_after_secs)

    logging.debug('{} STATUS'.format(proj_id))

    request_params = {
      'command': 'STATUS',
      'media_id': media_id
    }

    req = requests.get(url=app.config['MEDIA_ENDPOINT_URL'], params=request_params, auth=oauth_connection)

    processing_info = req.json().get('processing_info', None)
    check_status(processing_info, media_id, oauth_connection, proj_id)