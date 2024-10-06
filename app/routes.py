from flask import request, render_template, redirect, url_for, flash
from app import app, db
from app.models import Video, Rating, User
from app.forms import RegistrationForm, VideoForm
from flask_login import current_user, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt


@app.route('/')
def index():
    return render_template('base.html')

@app.route('/browse', methods=['GET'])
def browse_videos():
    page = request.args.get('page', 1, type=int)
    videos = Video.query.filter_by(hidden=False).paginate(page=page, per_page=10)

    return render_template('browse_videos.html', videos=videos)

@app.route('/rate/<int:video_id>', methods=['POST'])
def rate_video(video_id):
    like = request.form.get('like') == 'true'
    
    if current_user.is_authenticated:
        rating = Rating.query.filter_by(user_id=current_user.id, video_id=video_id).first()
        
        if rating:
            rating.like = like
        else:
            new_rating = Rating(video_id=video_id, user_id=current_user.id, like=like)
            db.session.add(new_rating)
        
        db.session.commit()
    
    return redirect(url_for('browse_videos'))

@app.route('/filter', methods=['GET'])
def filter_videos():
    category = request.args.get('category')
    page = request.args.get('page', 1, type=int)
    
    if category:
        videos = Video.query.filter_by(hidden=False, category=category).paginate(page=page, per_page=10)
    else:
        videos = Video.query.filter_by(hidden=False).paginate(page=page, per_page=10)
    
    return render_template('filter_videos.html', videos=videos, category=category)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.verify_password(password):
            login_user(user)
            return redirect(url_for('browse_videos'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/videos', methods=['GET'])
@login_required
def admin_videos():
    if not current_user.is_admin:  # Assuming you have an 'is_admin' flag in your User model
        flash("You don't have permission to access this page.")
        return redirect(url_for('index'))
    
    videos = Video.query.all()  # Fetch all videos from the database
    return render_template('admin/admin_videos.html', videos=videos)

@app.route('/admin/videos/manage', methods=['GET', 'POST'])
@login_required
def manage_videos():
    if not current_user.is_admin:
        flash("You don't have permission to access this page.")
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Handling video addition or deletion
        if 'add_video' in request.form:
            title = request.form['title']
            description = request.form['description']
            url = request.form['url']  # Assuming you're storing video URLs
            new_video = Video(title=title, description=description, url=url)
            db.session.add(new_video)
            db.session.commit()
            flash('Video added successfully!')
        elif 'delete_video' in request.form:
            video_id = request.form.get('video_id')
            if not video_id:
                return "Video ID is required", 400
            video = Video.query.get(video_id)
            if video:
                db.session.delete(video)
                db.session.commit()
                flash('Video deleted successfully!')
    
    videos = Video.query.all()
    return render_template('admin/manage_videos.html', videos=videos)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    bcrypt = Bcrypt()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/account/add_video', methods=['GET', 'POST'])
@login_required
def add_video():
    form = VideoForm()
    if form.validate_on_submit():
        if form.file_path.data and allowed_file(form.file_path.data.filename):
            filename = secure_filename(form.file_path.data.filename)
            # Сохраните файл в директорию static/video
            file_path = os.path.join('static', 'video', filename)
            full_path = os.path.join(app.root_path, file_path)
            print(f"file_path: {file_path} and filename: {filename}")
            form.file_path.data.save(full_path)

            video = Video(
                title=form.title.data,
                description=form.description.data,
                file_path=filename,  # Сохраняем относительный путь
                user_id=current_user.id
            )
            db.session.add(video)
            db.session.commit()
            flash('Video added successfully!', 'success')
            return redirect(url_for('account'))

    return render_template('add_video.html', form=form)

@app.route('/admin/ratings', methods=['GET'])
@login_required
def admin_ratings():
    if not current_user.is_admin:
        flash("You don't have permission to access this page.")
        return redirect(url_for('index'))
    
    ratings = Rating.query.all()
    return render_template('admin/ratings.html', ratings=ratings)

import json
from datetime import datetime

def log_action(user_id, action):
    log_entry = {
        "user_id": user_id,
        "action": action,
        "timestamp": datetime.utcnow().isoformat()
    }
    with open('user_actions.json', 'a') as log_file:
        log_file.write(json.dumps(log_entry) + '\n')

@app.route('/admin/logs', methods=['GET'])
@login_required
def admin_logs():
    if not current_user.is_admin:
        flash("You don't have permission to access this page.")
        return redirect(url_for('index'))
    
    with open('user_actions.json', 'r') as log_file:
        logs = [json.loads(line) for line in log_file]
    
    return render_template('admin/logs.html', logs=logs)
