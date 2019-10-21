from config import Config
import os, logging
from requests_oauthlib import OAuth1
import requests, random, time, json


import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow



# API Upload functions
def send_twitter(proj_id, stat, user_coid, user_uid, access_token, access_token_secret):
    """
    proj_id 
    twitter_status 
    user uid and coid
    access token and access token secret
    """
    
    creds = Config.OAUTH_CREDENTIALS['twitter']

    # File location
    VIDEO_FILENAME =  os.path.join('/mnt/csae48d5df47deax41bcxbaa/SherpaVideos/Videos/', str(proj_id), str(proj_id)+'_edited.mp4')

    logging.debug("Project {} for upload to Twitter".format(proj_id))
    logging.debug("Request made by user with coid={} and uid={}".format(user_uid, user_coid))
    logging.debug("Tweet body for {} is {} ".format(proj_id, stat))

    # Create OAuth1 flow
    oauth_connection = OAuth1(
        creds['id'],
        creds['secret'],
        access_token,
        access_token_secret
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

    req = requests.post(url=Config.MEDIA_ENDPOINT_URL, data=request_data, auth=oauth_connection)
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
        
        req = requests.post(url=Config.MEDIA_ENDPOINT_URL, data=request_data, files=files, auth=oauth_connection)

        # If status code isn't in 200 range, something has gone wrong
        if req.status_code < 200 or req.status_code > 299:
            logging.error("Error occured in uploading of file {}:\n Status Code: {} \n Details: {}".format(proj_id, req.status_code, req.text))
            return -1

        segment_id = segment_id + 1
        bytes_sent = file.tell()

        logging.debug('{} of {} bytes uploaded for {}'.format(str(bytes_sent), str(total_bytes), proj_id))

    logging.debug('Upload chunks complete for {}.'.format(proj_id))

    logging.debug("FINALIZE")

    request_data = {
      'command': 'FINALIZE',
      'media_id': media_id
    }

    req = requests.post(url=Config.MEDIA_ENDPOINT_URL, data=request_data, auth=oauth_connection)
    # TODO: review logging for json status for twitter
    #logging.debug(req.json())

    processing_info = req.json().get('processing_info', None)
    check_status(processing_info, media_id, oauth_connection, proj_id)

    request_data = {
      'status': stat,
      'media_ids': media_id
    }

    req = requests.post(url=Config.POST_TWEET_URL, data=request_data, auth=oauth_connection)
    logging.debug(req.json())

    twitter_status = "Uploaded successfully"
    logging.debug("File {} uploaded successfully".format(proj_id))
    return twitter_status


def send_youtube(proj_id, youtube_credentials, user_coid, user_uid, youtube_form):
    credentials = google.oauth2.credentials.Credentials(**youtube_credentials)
    
    VIDEO_FILENAME =  os.path.join('/mnt/csae48d5df47deax41bcxbaa/SherpaVideos/Videos/', str(proj_id), str(proj_id)+'_edited.mp4')
    
    logging.debug("Project {} for upload to Youtube".format(proj_id))
    logging.debug("Request made by user with coid={} and uid={}".format(user_coid, user_coid))

    youtube = build(
        "youtube", 
        "v3",
        credentials=credentials
    )

    body=dict(
        snippet=dict(
            title=youtube_form['title'],
            description=youtube_form['yt_desc'],
            tags=youtube_form['tags'],
            categoryId="22"
        ),
        status=dict(
            privacyStatus=youtube_form['privacy']
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


def send_facebook(proj_id, user_access_token, user_access_secret, title, body, user_uid, user_coid):
    url='https://graph-video.facebook.com/{}/videos?access_token={}'.format(
        user_access_token,
        user_access_secret
    )
    name = title
    desc = body
    VIDEO_LOC = os.path.join('/mnt/csae48d5df47deax41bcxbaa/SherpaVideos/Videos/', str(proj_id), str(proj_id)+'_edited.mp4')
    #VIDEO_LOC = os.path.join('N:/project/videos/', str(proj_id), str(proj_id)+'_edited.mp4')
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
    logging.debug("Request made by user with coid={} and uid={}".format(user_coid, user_uid))

    flag = requests.post(url, data=payload, files=files).text
    logging.debug(flag)
    fb_res = json.loads(flag)
    if not fb_res["error"]:
        logging.debug("Project {} uploaded successfully".format(proj_id))
        return "Video successfully uploaded to Facebook"
    else:
        logging.debug("Error occured in upload of {}\n{}".format(proj_id, fb_res))
        return "There was an error during upload. Please try again or contact the Video Sherpa administrators."



def check_status(processing_info, media_id, oauth_connection, proj_id):
    '''
    Checks video processing status
    '''
    if processing_info is None:
        logging.error("No processing data found for '{}'".format(proj_id))    
        return 0

    state = processing_info['state']

    logging.debug('Media processing status for {} is {}'.format(proj_id, state))

    if state == u'succeeded':
        logging.debug("Succeded Twitter upload for '{}'".format(proj_id))
        return 1

    if state == u'failed':
        logging.error("Twitter upload failed for '{}'".format(proj_id))
        return -1

    check_after_secs = processing_info['check_after_secs']
    
    logging.debug('Checking after {} seconds for {}'.format(str(check_after_secs), proj_id))
    time.sleep(check_after_secs)

    logging.debug('{} STATUS'.format(proj_id))

    request_params = {
      'command': 'STATUS',
      'media_id': media_id
    }

    req = requests.get(url=Config.MEDIA_ENDPOINT_URL, params=request_params, auth=oauth_connection)

    processing_info = req.json().get('processing_info', None)
    check_status(processing_info, media_id, oauth_connection, proj_id)


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
            if e.resp.status in Config.RETRIABLE_STATUS_CODES:
                error = "A retriable HTTP error {} occurred for {}:\n Content: {}".format(e.resp.status, proj_id, e.content)
            else:
                raise
        except Config.RETRIABLE_EXCEPTIONS as e:
            error = "A retriable error occurred for {}: {}".format(proj_id, e)
        
        if error is not None:
            logging.error(error)
            retry += 1
        if retry > Config.MAX_RETRIES:
            logging.error("No longer attempting to retry for {}.".format(proj_id))
            exit("No longer attempting to retry.")
        
        max_sleep = 2 ** retry
        sleep_seconds = random.random() * max_sleep
        logging.debug("Sleeping {} seconds and then retrying for {}...".format(sleep_seconds, proj_id))
        time.sleep(sleep_seconds)

