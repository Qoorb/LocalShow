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
    Optional,
)


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
