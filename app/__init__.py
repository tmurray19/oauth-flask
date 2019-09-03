from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

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

from app import routes, models
