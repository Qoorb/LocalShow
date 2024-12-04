from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import os


app = Flask(__name__, static_folder="static")
app.config.from_object("config.Config")

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "video")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

admin_login_manager = LoginManager(app)
admin_login_manager.login_view = "admin_login"

from app.models import User


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@admin_login_manager.user_loader
def load_admin_user(user_id):
    return User.query.get(int(user_id))


from app import routes, models
