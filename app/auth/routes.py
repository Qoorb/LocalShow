from flask import (
    render_template, redirect,
    url_for, flash, request
)
from flask_bcrypt import Bcrypt  # type: ignore
from flask_login import (  # type: ignore
    current_user, login_user, LoginManager,
    logout_user, login_required
)

from app import db
from app.auth import bp
from app.models import User
from app.utils import log_action

from .forms import RegistrationForm


login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, is_admin=False).first()

        if user and user.verify_password(password):
            login_user(user)
            log_action(user.id, "выполнил вход в систему")
            return redirect(url_for("main.browse_videos"))
        else:
            flash("Неверное имя пользователя или пароль.")

    return render_template("auth/login.html")


@bp.route("/register", methods=["GET", "POST"])
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
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", title="Register", form=form)


@bp.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    log_action(user_id, "вышел из системы")
    return redirect(url_for("main.index"))
