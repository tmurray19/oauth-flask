import os
import httplib2
import http.client

basedir = os.path.abspath(os.path.dirname(__file__))


# Config file
class Config(object):
    # Secret key used for verification
    # or statements are used as a fallback
    SECRET_KEY = os.environ.get('SECRET_KEY') or "WgnYVzwgwF7Alu1B3DehuO-C-QoKcBitsHqpiFi1cRE"
    # SQL Database location
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    # Directories
    BASE_DIR = os.environ.get('BASE_DIR') or "/mnt/csae48d5df47deax41bcxbaa/SherpaVideos/"
    #BASE_DIR = os.environ.get('BASE_DIR') or "N:/project"
    VIDS_LOCATION = os.environ.get('VIDS_LOCATION') or "Videos"
    LOGS_LOCATION = os.environ.get('LOGS_LOCATION') or "logs" 
    AUTH_LOG = os.environ.get('AUTH_LOG') or 'authFlask'
    UPLOAD_QUEUE = os.environ.get('UPLOAD_QUEUE') or 'uploadQueue'
    UPLOAD_LOGS = os.environ.get('UPLOAD_LOGS') or 'uploadWatcher'

    OAUTH_CREDENTIALS = os.environ.get('OAUTH_CREDENTIALS') or {
        'facebook': {
            'id': '1400329783451742',
            'secret': '35eb5e369af963d7f2f1679cafaf2b96'
        },
        'twitter': {
            'id': 'UID4eI5FJv1yeyoiuPW8aHE3X',
            'secret': 'PxZCfzdDfzAl5ofk2pSJsrTmwOpy4Bh9OUHuJuIsIEoWx3jfip'
        },
        'google': {
            'id': '705996956550-pdtpes13chavp1sl2j6vpei968n1hach.apps.googleusercontent.com',
            'secret': 'BCnxYZeVVC7e4RS7evTh5P8D'
        },
        'linkedin': {
            'id': '8629lxwlldj1oo',
            'secret': 'jhJNdYStdzMSoHaJ'
        }
    }


    """ 
    Here is the youtube related information
    """
    httplib2.RETRIES = 1

    MAX_RETRIES = 10

    RETRIABLE_EXCEPTIONS = (httplib2.HttpLib2Error, IOError, http.client.NotConnected,
    http.client.IncompleteRead, http.client.ImproperConnectionState,
    http.client.CannotSendRequest, http.client.CannotSendHeader,
    http.client.ResponseNotReady, http.client.BadStatusLine)

    RETRIABLE_STATUS_CODES = [500, 502, 503, 504]
    
    #CLIENT_SECRETS_FILE = "N:/sherpa-oauth/client_secrets.json"
    CLIENT_SECRETS_FILE = "/home/sherpa-render/auth-sherpa/client_secrets.json"

    YOUTUBE_UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload"
    YOUTUBE_API_SERVICE_NAME = "youtube"
    YOUTUBE_API_VERSION = "v3"

    MISSING_CLIENT_SECRETS_MESSAGE = """
    WARNING: Please configure OAuth 2.0

    To make this sample run you will need to populate the client_secrets.json file
    found at:

    %s

    with information from the Developers Console
    https://console.developers.google.com/

    For more information about the client_secrets.json file format, please visit:
    https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
    """ % os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    CLIENT_SECRETS_FILE))

    VALID_PRIVACY_STATUSES = ("public", "private", "unlisted")
    SCOPES = [
        'https://www.googleapis.com/auth/youtube.force-ssl', 
        'https://www.googleapis.com/auth/youtube.upload', 
        "https://www.googleapis.com/auth/userinfo.email", 
        "openid"
    ]

    """
    Here is the twitter
    """
        
    MEDIA_ENDPOINT_URL = 'https://upload.twitter.com/1.1/media/upload.json'
    POST_TWEET_URL = 'https://api.twitter.com/1.1/statuses/update.json'