from flask import request, render_template, redirect, url_for, flash
from app import app, db
from app.models import Video, Rating, User
from flask_login import current_user, login_user, logout_user, login_required


@app.route('/')
def index():
    return render_template('base.html')

@app.route('/browse', methods=['GET'])
@login_required
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
