from flask import Blueprint


bp = Blueprint('video', __name__)

from app.video import routes
