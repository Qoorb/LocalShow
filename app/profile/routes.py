from flask import (
    render_template, redirect,
    url_for, flash, request
)
from flask_bcrypt import Bcrypt  # type: ignore
from flask_login import current_user, login_required  # type: ignore

from app import db
from app.profile import bp
from app.models import Video, User

from .forms import EditProfileForm


@bp.route("/account")
@login_required
def account():
    user_videos = (
        Video.query.filter_by(user_id=current_user.id)
        .order_by(Video.created_at.desc())
        .all()
    )
    return render_template(
        "profile/account.html",
        user=current_user,
        user_videos=user_videos
    )


@bp.route("/account/edit", methods=["GET", "POST"])
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
            return render_template("profile/edit_profile.html", form=form)

        if (
            form.email.data != current_user.email
            and User.query.filter_by(email=form.email.data).first()
        ):
            flash("Этот email уже используется.", "danger")
            return render_template("profile/edit_profile.html", form=form)

        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.new_password.data:
            current_user.password_hash = bcrypt.generate_password_hash(
                form.new_password.data
            ).decode("utf-8")
        db.session.commit()
        flash("Профиль успешно обновлен!", "success")
        return redirect(url_for("profile.account"))

    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template("profile/edit_account.html", form=form)
