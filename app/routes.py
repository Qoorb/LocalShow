from flask import (
    request, current_app, render_template,
    redirect, url_for, flash, abort
)
from flask_bcrypt import Bcrypt  # type: ignore
from flask_login import (  # type: ignore
    current_user, login_user,
    logout_user, login_required
)
from werkzeug.utils import secure_filename
from sqlalchemy import func, case

import os

from app import app, db
from app.models import Video, Rating, User, Category, Log
from app.forms import RegistrationForm, VideoForm, EditProfileForm

from .utils import allowed_file, log_action


@app.route("/")
def index():
    return redirect(url_for("browse_videos"))


@app.route("/browse", methods=["GET"])
def browse_videos():
    page = request.args.get("page", 1, type=int)
    videos = Video.query.filter_by(hidden=False).paginate(
        page=page, per_page=10
    )

    return render_template("browse_videos.html", videos=videos)


@app.route("/filter", methods=["GET"])
def filter_videos():
    category_name = request.args.get("category")
    page = request.args.get("page", 1, type=int)
    query = Video.query.filter_by(hidden=False)

    if category_name:
        query = query.join(Video.category).filter(
            Category.name == category_name
        )

    videos = query.paginate(page=page, per_page=10)
    return render_template(
        "filter_videos.html",
        videos=videos,
        category=category_name
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, is_admin=False).first()

        if user and user.verify_password(password):
            login_user(user)
            log_action(user.id, "выполнил вход в систему")
            return redirect(url_for("browse_videos"))
        else:
            flash("Неверное имя пользователя или пароль.")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    bcrypt = Bcrypt()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data
        ).decode("utf-8")
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        log_action(user.id, "зарегистрировался в системе")
        flash(
            "Ваш аккаунт был создан! Вы можете теперь войти в систему.",
            "success"
        )
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)


@app.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    log_action(user_id, "вышел из системы")
    return redirect(url_for("index"))


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
            flash(
                "Пожалуйста, войдите в систему, чтобы оценить видео.",
                "warning"
            )

        return redirect(url_for("video_view", video_id=video_id))

    ratings = (
        db.session.query(
            func.count(Rating.id).label("total_ratings"),
            func.sum(case((Rating.like.is_(True), 1), else_=0))
            .label("likes"),
            func.sum(case((Rating.like.is_(False), 1), else_=0))
            .label("dislikes"),
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


@app.route("/video/<int:video_id>/edit", methods=["GET", "POST"])
@login_required
def edit_video(video_id):
    video = Video.query.get_or_404(video_id)
    if video.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    form = VideoForm()
    if form.validate_on_submit():
        video.title = form.title.data
        video.description = form.description.data
        video.category_id = form.category.data
        db.session.commit()
        flash("Видео успешно обновлено!", "success")
        return redirect(url_for("account"))

    elif request.method == "GET":
        form.title.data = video.title
        form.description.data = video.description
        form.category.data = video.category_id

    return render_template("edit_video.html", form=form, video=video)


@app.route("/video/<int:video_id>/delete", methods=["POST"])
@login_required
def delete_video(video_id):
    video = Video.query.get_or_404(video_id)
    if video.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    try:
        file_path = os.path.join(
            current_app.config["UPLOAD_FOLDER"],
            video.file_path
        )
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(video)
        db.session.commit()
        flash("Видео успешно удалено!", "success")
    except Exception as e:
        app.logger.error(f"Ошибка при удалении видео: {e}")
        flash("Произошла ошибка при удалении видео.", "danger")
    return redirect(url_for("account"))


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
            new_rating = Rating(
                video_id=video_id,
                user_id=current_user.id,
                like=like
            )
            db.session.add(new_rating)
            action = "добавил рейтинг"

        db.session.commit()
        log_action(current_user.id, f"{action} для видео {video_id}")

    return redirect(url_for("video_view", video_id=video_id))


@app.route("/account")
@login_required
def account():
    user_videos = (
        Video.query.filter_by(user_id=current_user.id)
        .order_by(Video.created_at.desc())
        .all()
    )
    return render_template(
        "account.html",
        user=current_user,
        user_videos=user_videos
    )


@app.route("/account/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))

    bcrypt = Bcrypt()
    form = EditProfileForm()
    if form.validate_on_submit():
        if (
            form.username.data != current_user.username
            and User.query.filter_by(username=form.username.data).first()
        ):
            flash("Это имя пользователя уже занято.", "danger")
            return render_template("edit_profile.html", form=form)

        if (
            form.email.data != current_user.email
            and User.query.filter_by(email=form.email.data).first()
        ):
            flash("Этот email уже используется.", "danger")
            return render_template("edit_profile.html", form=form)

        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.new_password.data:
            current_user.password_hash = bcrypt.generate_password_hash(
                form.new_password.data
            ).decode("utf-8")
        db.session.commit()
        flash("Профиль успешно обновлен!", "success")
        return redirect(url_for("account"))

    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template("edit_profile.html", form=form)


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
            log_action(
                current_user.id,
                f"загрузил новое видео: {form.title.data}"
            )
            flash("Video added successfully!", "success")
            return redirect(url_for("account"))

    return render_template("add_video.html", form=form)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        else:
            flash("У вас нет прав администратора.", "danger")
            return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, is_admin=True).first()

        if user and user.verify_password(password):
            login_user(user)
            log_action(user.id, "выполнил вход как администратор")
            return redirect(url_for("admin_dashboard"))
        else:
            flash(
                "Неверное имя пользователя или пароль администратора.",
                "danger"
            )

    return render_template("admin/login.html")


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin_login"))
    return render_template("admin/dashboard.html")


@app.route("/admin/videos", methods=["GET", "POST"])
@login_required
def admin_videos():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin_login"))

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


@app.route("/admin/videos/manage", methods=["GET", "POST"])
@login_required
def admin_manage_videos():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        if "delete_video" in request.form:
            video_id = request.form.get("video_id")
            if not video_id:
                flash("Не указан ID видео для удаления.", "danger")
                return redirect(url_for("admin_manage_videos"))

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


@app.route("/admin/ratings")
@login_required
def admin_ratings():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin_login"))
    try:
        ratings = (
            db.session.query(
                Video.id,
                Video.title,
                func.count(Rating.id).label("total_ratings"),
                func.sum(case((Rating.like.is_(True), 1), else_=0))
                .label("likes"),
                func.sum(case((Rating.like.is_(False), 1), else_=0))
                .label("dislikes"),
            )
            .outerjoin(Rating)
            .group_by(Video.id, Video.title)
            .all()
        )

        return render_template("admin/ratings.html", ratings=ratings)
    except Exception as e:
        app.logger.error(f"Error fetching ratings: {e}")
        return "Internal Server Error", 500


@app.route("/admin/logs")
@login_required
def admin_logs():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin_login"))

    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template("admin/logs.html", logs=logs)
