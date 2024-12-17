from flask import (
    render_template, redirect, current_app,
    url_for, flash, request, abort
)
from flask_login import current_user, login_required  # type: ignore
from werkzeug.utils import secure_filename
from sqlalchemy import func, case

import os

from app import db, app
from app.video import bp
from app.models import Video, Rating
from app.utils import allowed_file, log_action

from .forms import VideoForm


@bp.route("/video/<int:video_id>", methods=["GET", "POST"])
def video_view(video_id):
    video = Video.query.get_or_404(video_id)

    if video.hidden and (
        not current_user.is_authenticated or not current_user.is_admin
    ):
        flash("Это видео недоступно.", "danger")
        return redirect(url_for("main.browse_videos"))

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

        return redirect(url_for("video.video_view", video_id=video_id))

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
        "video/video_view.html",
        video=video,
        total_ratings=total_ratings,
        likes=likes,
        dislikes=dislikes,
    )


@bp.route("/video/<int:video_id>/edit", methods=["GET", "POST"])
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
        return redirect(url_for("profile.account"))

    elif request.method == "GET":
        form.title.data = video.title
        form.description.data = video.description
        form.category.data = video.category_id

    return render_template("video/edit_video.html", form=form, video=video)


@bp.route("/video/<int:video_id>/delete", methods=["POST"])
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
    return redirect(url_for("profile.account"))


@bp.route("/video/<int:video_id>/rate", methods=["POST"])
@login_required
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

    return redirect(url_for("video.video_view", video_id=video_id))


@bp.route("/video/add_video/", methods=["GET", "POST"])
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
                f"добавил новое видео: {form.title.data}"
            )
            flash("Видео успешно добавлено!", "success")
            return redirect(url_for("profile.account"))

    return render_template("video/add_video.html", form=form)
