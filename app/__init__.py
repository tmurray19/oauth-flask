from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from datetime import datetime
import logging, os

# Initialising Code
app = Flask(__name__)
# Config file
app.config.from_object(Config)
# Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)
# Login manager
login = LoginManager(app)
login.login_view = 'index'
"""log_name = os.path.join(app.config['BASE_DIR'], app.config['LOGS_LOCATION'], app.config['AUTH_LOG'], datetime.now().strftime("%Y-%m-%d-%H-%M-%S")+"_auth_flask_instance.log")
logging.basicConfig(
    level=logging.DEBUG,        
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename=log_name
)
logging.debug("Auth flask instance started")"""

from app import routes, models
