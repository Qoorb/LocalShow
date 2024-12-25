from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # type: ignore
from flask_bcrypt import Bcrypt  # type: ignore
import os


db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()


def create_app(config_class=None):
    app = Flask(__name__, static_folder="static")

    if config_class is None:
        app.config.from_object("config.Config")
    else:
        app.config.from_object(config_class)

    UPLOAD_FOLDER = os.path.join(app.root_path, "static", "video")
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)

    from app.auth.routes import login_manager
    from app.admin.routes import admin_login_manager

    login_manager.init_app(app)
    admin_login_manager.init_app(app)

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from app.profile import bp as profile_bp
    app.register_blueprint(profile_bp)

    from app.video import bp as video_bp
    app.register_blueprint(video_bp)

    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    return app
