from flask_wtf import FlaskForm  # type: ignore
from wtforms import (  # type: ignore
    StringField,
    PasswordField,
    SubmitField,
)
from wtforms.validators import (  # type: ignore
    DataRequired,
    Length,
    Email,
    EqualTo,
    ValidationError,
)
from app.models import User


class RegistrationForm(FlaskForm):
    username = StringField(
        "Имя пользователя", validators=[DataRequired(), Length(min=2, max=20)]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Подтвердите пароль", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Зарегистрироваться")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                "That username is taken. Please choose a different one."
            )

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                "That email is already in use. Please choose a different one."
            )
