import os

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

    OAUTH_CREDENTIALS = os.environ.get('OAUTH_CREDENTIALS') or {
        'facebook': {
            'id': 'N/A',
            'secret': 'N/A'
        },
        'twitter': {
            'id': 'Q64HOqkOgyeCGXZykvt6gIJur',
            'secret': 'W03elioGV05UMeFAnSCR7gqseIpGMmvUoprGPW5kSrz9boE7af'
        },
        'google': {
            'id': '705996956550-pdtpes13chavp1sl2j6vpei968n1hach.apps.googleusercontent.com',
            'secret': 'BCnxYZeVVC7e4RS7evTh5P8D'
        }
    }