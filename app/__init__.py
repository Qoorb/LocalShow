from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import os


app = Flask(__name__)
app.config.from_object('config.Config')

UPLOAD_FOLDER = os.path.normpath('app\\static\\video')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

from app.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


from app import routes, models
