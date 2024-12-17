from flask import (
    request, render_template,
    redirect, url_for, flash, abort, send_file
)
from flask_login import (  # type: ignore
    current_user, login_user,
    login_required
)
from werkzeug.utils import secure_filename
from sqlalchemy import func, case

import os
import xml.etree.ElementTree as ET
import json
import tempfile

from app import app, db
from app.admin import bp
from app.models import Video, Rating, User, Log
from app.video.forms import VideoForm
from app.utils import allowed_file, log_action


@bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin.admin_dashboard"))
        else:
            flash("У вас нет прав администратора.", "danger")
            return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, is_admin=True).first()

        if user and user.verify_password(password):
            login_user(user)
            log_action(user.id, "выполнил вход как администратор")
            return redirect(url_for("admin.admin_dashboard"))
        else:
            flash(
                "Неверное имя пользователя или пароль администратора.",
                "danger"
            )

    return render_template("admin/login.html")


@bp.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin.admin_login"))
    return render_template("admin/dashboard.html")


@bp.route("/admin/videos", methods=["GET", "POST"])
@login_required
def admin_videos():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin.admin_login"))

    title = request.args.get('title', '').strip()
    description = request.args.get('description', '').strip()
    username = request.args.get('username', '').strip()

    query = Video.query.join(User)

    if title:
        query = query.filter(Video.title.ilike(f'%{title}%'))
    if description:
        query = query.filter(Video.description.ilike(f'%{description}%'))
    if username:
        query = query.filter(User.username.ilike(f'%{username}%'))

    if request.method == "POST":
        video_id = request.form.get("video_id")
        if video_id:
            video = Video.query.get_or_404(video_id)
            video.hidden = not video.hidden
            db.session.commit()
            flash(
                f"Видео {'скрыто' if video.hidden else 'показано'}.",
                "success"
            )
            return redirect(url_for("admin.admin_videos"))

    page = request.args.get('page', 1, type=int)
    videos = query.order_by(Video.created_at.desc()).paginate(
        page=page, per_page=10
    )

    return render_template("admin/admin_videos.html", videos=videos)


@bp.route("/admin/manage_videos", methods=["GET", "POST"])
@login_required
def admin_manage_videos():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin_login"))

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
            return redirect(url_for("admin.admin_manage_videos"))

    return render_template("admin/manage_videos.html", form=form)


@bp.route("/admin/ratings", methods=["GET"])
@login_required
def admin_ratings():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin.admin_login"))

    sort_by = request.args.get("sort_by", "total_ratings")
    sort_order = request.args.get("sort_order", "desc")
    page = request.args.get("page", 1, type=int)

    try:
        query = db.session.query(
            Video.id,
            Video.title,
            func.count(Rating.id).label("total_ratings"),
            func.sum(
                case((Rating.like.is_(True), 1), else_=0)
            ).label("likes"),
            func.sum(
                case((Rating.like.is_(False), 1), else_=0)
            ).label("dislikes"),
        ).outerjoin(Rating).group_by(Video.id, Video.title)

        if sort_by == "total_ratings":
            if sort_order == "asc":
                query = query.order_by(func.count(Rating.id).asc())
            else:
                query = query.order_by(func.count(Rating.id).desc())
        elif sort_by in ['id', 'title']:
            if sort_order == "asc":
                query = query.order_by(getattr(Video, sort_by).asc())
            else:
                query = query.order_by(getattr(Video, sort_by).desc())
        else:
            query = query.order_by(func.count(Rating.id).desc())

        ratings = query.paginate(page=page, per_page=10)

        return render_template(
            "admin/ratings.html",
            ratings=ratings.items,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page
        )
    except Exception as e:
        app.logger.error(f"Error fetching ratings: {e}")
        return "Internal Server Error", 500


@bp.route("/admin/logs")
@login_required
def admin_logs():
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin.admin_login"))

    page = request.args.get("page", 1, type=int)
    logs = Log.query.join(User).order_by(Log.timestamp.desc()).paginate(
        page=page, per_page=50
    )
    return render_template("admin/logs.html", logs=logs)


@bp.route("/admin/logs/export/<format>")
@login_required
def export_logs(format):
    if not current_user.is_admin:
        flash("Доступ запрещен.", "danger")
        return redirect(url_for("admin_login"))

    logs = Log.query.join(User).order_by(Log.timestamp.desc()).all()

    if format == 'txt':
        output = '\n'.join([
            f"[{log.timestamp}] {log.user.username}"
            f"(ID: {log.user_id}): {log.action}"
            for log in logs
        ])
        mime_type = 'text/plain'
        filename = 'logs.txt'

    elif format == 'xml':
        root = ET.Element('logs')
        for log in logs:
            log_elem = ET.SubElement(root, 'log')
            ET.SubElement(
                log_elem,
                'timestamp'
            ).text = log.timestamp.isoformat()
            ET.SubElement(log_elem, 'username').text = log.user.username
            ET.SubElement(log_elem, 'user_id').text = str(log.user_id)
            ET.SubElement(log_elem, 'action').text = log.action

        output = ET.tostring(root, encoding='unicode', method='xml')
        mime_type = 'application/xml'
        filename = 'logs.xml'

    elif format == 'json':
        output = json.dumps([{
            'timestamp': log.timestamp.isoformat(),
            'username': log.user.username,
            'user_id': log.user_id,
            'action': log.action
        } for log in logs], ensure_ascii=False, indent=2)
        mime_type = 'application/json'
        filename = 'logs.json'

    else:
        abort(400)

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(output)
        temp_path = f.name

    return send_file(
        temp_path,
        mimetype=mime_type,
        as_attachment=True,
        download_name=filename
    )


@bp.route("/admin/videos/<int:video_id>/edit", methods=["GET", "POST"])
@login_required
def admin_edit_video(video_id):
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin.admin_login"))

    video = Video.query.get_or_404(video_id)
    form = VideoForm()

    if form.validate_on_submit():
        video.title = form.title.data
        video.description = form.description.data
        video.category_id = form.category.data
        db.session.commit()
        log_action(current_user.id, f"отредактировал видео: {video.title}")
        flash("Видео успешно обновлено!", "success")
        return redirect(url_for("admin.admin_videos"))

    elif request.method == "GET":
        form.title.data = video.title
        form.description.data = video.description
        form.category.data = video.category_id

    return render_template("admin/edit_video.html", form=form, video=video)


@bp.route("/admin/videos/<int:video_id>/view")
@login_required
def admin_view_video(video_id):
    if not current_user.is_admin:
        flash(
            "Доступ запрещен. Пожалуйста, войдите как администратор.",
            "danger"
        )
        return redirect(url_for("admin.admin_login"))

    video = Video.query.get_or_404(video_id)

    ratings = (
        db.session.query(
            func.count(Rating.id).label("total_ratings"),
            func.sum(
                case((Rating.like.is_(True), 1), else_=0)
            ).label("likes"),
            func.sum(
                case((Rating.like.is_(False), 1), else_=0)
            ).label("dislikes"),
        )
        .filter_by(video_id=video_id)
        .first()
    )

    uploader = User.query.get(video.user_id)

    recent_ratings = (
        Rating.query
        .join(User)
        .filter(Rating.video_id == video_id)
        .order_by(Rating.timestamp.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "admin/view_video.html",
        video=video,
        uploader=uploader,
        total_ratings=ratings.total_ratings or 0,
        likes=ratings.likes or 0,
        dislikes=ratings.dislikes or 0,
        recent_ratings=recent_ratings
    )
