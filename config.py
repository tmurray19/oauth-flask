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
    BASE_DIR = os.environ.get('BASE_DIR') or "/mnt/csae48d5df47deax41bcxbaa"
    LOGS_LOCATION = os.environ.get('LOGS_LOCATION') or "logs" 
    AUTH_LOG = os.environ.get('AUTH_LOG') or 'authFlask'

    OAUTH_CREDENTIALS = os.environ.get('OAUTH_CREDENTIALS') or {
        'facebook': {
            'id': '1209619439222314',
            'secret': 'e7ab5768f06f329206e960e0965eb78c'
        },
        'twitter': {
            'id': 'tJr2grTKu1j0NKH6YuHy4KQxI',
            'secret': 'Qj6SJZWFSVio8ORuALs0nuFc3aVmL6gsHwndkJF6AWYRWnMT3e'
        },
        'google': {
            'id': 'N/A',
            'secret': 'N/A'
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
    
    #CLIENT_SECRETS_FILE = "N:/oath/flask-oauth-example/client_secrets.json"
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