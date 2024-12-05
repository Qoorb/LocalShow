from flask_wtf import FlaskForm  # type: ignore
from wtforms import (  # type: ignore
    StringField,
    PasswordField,
    SubmitField,
    TextAreaField,
    FileField,
    SelectField,
)
from wtforms.validators import (  # type: ignore
    DataRequired,
    Length,
    Email,
    EqualTo,
    ValidationError,
    Optional,
)
from app.models import User, Category


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


class VideoForm(FlaskForm):
    title = StringField("Название", validators=[DataRequired()])
    description = TextAreaField("Описание", validators=[DataRequired()])
    file_path = FileField("Загрузить Видео", validators=[DataRequired()])
    category = SelectField(
        "Категория", choices=[], coerce=int, validators=[DataRequired()]
    )
    submit = SubmitField("Добавить Видео")

    def __init__(self, *args, **kwargs):
        super(VideoForm, self).__init__(*args, **kwargs)
        self.category.choices = [
            (category.id, category.name)
            for category in Category.query.order_by("name")
        ]


class EditProfileForm(FlaskForm):
    username = StringField(
        "Имя пользователя", validators=[DataRequired(), Length(min=2, max=20)]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    new_password = PasswordField(
        "Новый пароль",
        validators=[Optional(), Length(min=6)]
    )
    confirm_password = PasswordField(
        "Подтвердите новый пароль",
        validators=[
            EqualTo(
                "new_password",
                message="Пароли должны совпадать"
            )
        ],
    )
    submit = SubmitField("Сохранить изменения")
