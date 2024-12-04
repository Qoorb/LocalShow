from flask import request, render_template, redirect, url_for, flash
from app import app, db
from app.models import Video, Rating, User, Category, Log
from app.forms import RegistrationForm, VideoForm
from flask_login import current_user, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from sqlalchemy import func, case
import os
from werkzeug.utils import secure_filename
from flask import current_app
import json
from datetime import datetime


@app.route("/")
def index():
    return render_template("base.html")


@app.route("/browse", methods=["GET"])
def browse_videos():
    page = request.args.get("page", 1, type=int)
    videos = Video.query.filter_by(hidden=False).paginate(page=page, per_page=10)

    return render_template("browse_videos.html", videos=videos)


@app.route("/rate/<int:video_id>", methods=["POST"])
def rate_video(video_id):
    like = request.form.get("like") == "true"

    if current_user.is_authenticated:
        rating = Rating.query.filter_by(
            user_id=current_user.id, video_id=video_id
        ).first()

        if rating:
            rating.like = like
            action = "обновил рейтинг"
        else:
            new_rating = Rating(video_id=video_id, user_id=current_user.id, like=like)
            db.session.add(new_rating)
            action = "добавил рейтинг"

        db.session.commit()
        log_action(current_user.id, f"{action} для видео {video_id}")

    return redirect(url_for("video_view", video_id=video_id))


@app.route("/filter", methods=["GET"])
def filter_videos():
    category_name = request.args.get("category")
    page = request.args.get("page", 1, type=int)
    query = Video.query.filter_by(hidden=False)

    if category_name:
        query = query.join(Video.category).filter(Category.name == category_name)

    videos = query.paginate(page=page, per_page=10)
    return render_template("filter_videos.html", videos=videos, category=category_name)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()

        if user and user.verify_password(password):
            login_user(user)
            log_action(user.id, "выполнил вход в систему")
            return redirect(url_for("browse_videos"))
        else:
            flash("Неверное имя пользователя или пароль.")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    log_action(user_id, "вышел из системы")
    return redirect(url_for("index"))


@app.route("/admin/videos", methods=["GET", "POST"])
@login_required
def admin_videos():
    if not current_user.is_admin:
        flash("У вас нет разрешения на доступ к этой странице.")
        return redirect(url_for("index"))

    if request.method == "POST":
        video_id = request.form.get("video_id")
        video = Video.query.get(video_id)
        if video:
            video.hidden = not video.hidden
            db.session.commit()
            flash(f'Статус видео "{video.title}" обновлен.', "success")
        else:
            flash("Видео не найдено.", "danger")

    videos = Video.query.all()
    return render_template("admin/admin_videos.html", videos=videos)


ALLOWED_EXTENSIONS = {"mp4", "avi", "mov"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/admin/videos/manage", methods=["GET", "POST"])
@login_required
def manage_videos():
    if not current_user.is_admin:
        flash("У вас нет разрешения на доступ к этой странице.")
        return redirect(url_for("index"))

    if request.method == "POST":
        if "delete_video" in request.form:
            video_id = request.form.get("video_id")
            if not video_id:
                flash("Не указан ID видео для удаления.", "danger")
                return redirect(url_for("manage_videos"))

            video = Video.query.get(video_id)
            if video:
                try:
                    file_path = os.path.join(
                        current_app.config["UPLOAD_FOLDER"], video.file_path
                    )
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    video_title = video.title
                    db.session.delete(video)
                    db.session.commit()
                    log_action(current_user.id, f"удалил видео: {video_title}")
                    flash("Видео успешно удалено!", "success")
                except Exception as e:
                    app.logger.error(f"Ошибка при удалении видео: {e}")
                    flash("Произошла ошибка при удалении видео.", "danger")

    videos = Video.query.all()
    return render_template("admin/manage_videos.html", videos=videos)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    bcrypt = Bcrypt()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        log_action(user.id, "зарегистрировался в системе")
        flash("Ваш аккаунт был создан! Вы можете теперь войти в систему.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)


@app.route("/account")
@login_required
def account():
    return render_template("account.html", user=current_user)


@app.route("/account/add_video", methods=["GET", "POST"])
@login_required
def add_video():
    form = VideoForm()
    if form.validate_on_submit():
        if form.file_path.data and allowed_file(form.file_path.data.filename):
            filename = secure_filename(form.file_path.data.filename)
            file_path = os.path.join("static", "video", filename)
            full_path = os.path.join(app.root_path, file_path)
            form.file_path.data.save(full_path)

            video = Video(
                title=form.title.data,
                description=form.description.data,
                file_path=filename,
                category_id=form.category.data,
                user_id=current_user.id,
            )
            db.session.add(video)
            db.session.commit()
            log_action(current_user.id, f"загрузил новое видео: {form.title.data}")
            flash("Video added successfully!", "success")
            return redirect(url_for("account"))

    return render_template("add_video.html", form=form)


@app.route("/admin/ratings", methods=["GET"])
@login_required
def admin_ratings():
    if not current_user.is_admin:
        flash("У вас нет разрешения на доступ к этой странице.")
        return redirect(url_for("index"))

    try:
        # Запрос для получения количества лайков и дизлайков для каждого видео
        ratings = (
            db.session.query(
                Video.id,
                Video.title,
                func.count(Rating.id).label("total_ratings"),
                func.sum(case((Rating.like == True, 1), else_=0)).label("likes"),
                func.sum(case((Rating.like == False, 1), else_=0)).label("dislikes"),
            )
            .outerjoin(Rating)
            .group_by(Video.id, Video.title)
            .all()
        )

        return render_template("admin/ratings.html", ratings=ratings)
    except Exception as e:
        app.logger.error(f"Error fetching ratings: {e}")
        return "Internal Server Error", 500


def log_action(user_id, action):
    # Сохранение в базу данных
    log_entry = Log(user_id=user_id, action=action)
    db.session.add(log_entry)
    db.session.commit()

    # Сохранение в JSON файл
    json_log = {
        "user_id": user_id,
        "action": action,
        "timestamp": datetime.utcnow().isoformat(),
    }

    log_file_path = os.path.join(app.root_path, "logs", "user_actions.json")
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

    try:
        # Читаем существующие логи
        if os.path.exists(log_file_path):
            with open(log_file_path, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
        else:
            logs = []

        # Добавляем новый лог
        logs.append(json_log)

        # Записываем обновленные логи
        with open(log_file_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)

    except Exception as e:
        app.logger.error(f"Ошибка при сохранении лога в JSON: {e}")


@app.route("/admin/logs", methods=["GET"])
@login_required
def admin_logs():
    if not current_user.is_admin:
        flash("У вас нет разрешения на доступ к этой странице.")
        return redirect(url_for("index"))

    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template("admin/logs.html", logs=logs)


@app.route("/video/<int:video_id>", methods=["GET", "POST"])
def video_view(video_id):
    video = Video.query.get_or_404(video_id)

    if video.hidden and (
        not current_user.is_authenticated or not current_user.is_admin
    ):
        flash("Это видео недоступно.", "danger")
        return redirect(url_for("browse_videos"))

    if request.method == "POST":
        like = request.form.get("like") == "true"

        if current_user.is_authenticated:
            rating = Rating.query.filter_by(
                user_id=current_user.id, video_id=video_id
            ).first()

            if rating:
                rating.like = like
            else:
                new_rating = Rating(
                    video_id=video_id, user_id=current_user.id, like=like
                )
                db.session.add(new_rating)

            db.session.commit()
            flash("Ваш отзыв был учтен.", "success")
        else:
            flash("Пожалуйста, войдите в систему, чтобы оценить видео.", "warning")

        return redirect(url_for("video_view", video_id=video_id))

    # Получение количества лайков и дизлайков
    ratings = (
        db.session.query(
            func.count(Rating.id).label("total_ratings"),
            func.sum(case((Rating.like == True, 1), else_=0)).label("likes"),
            func.sum(case((Rating.like == False, 1), else_=0)).label("dislikes"),
        )
        .filter_by(video_id=video_id)
        .first()
    )

    total_ratings = ratings.total_ratings or 0
    likes = ratings.likes or 0
    dislikes = ratings.dislikes or 0

    return render_template(
        "video_view.html",
        video=video,
        total_ratings=total_ratings,
        likes=likes,
        dislikes=dislikes,
    )
