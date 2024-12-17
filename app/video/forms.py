from flask_wtf import FlaskForm  # type: ignore
from wtforms import (  # type: ignore
    StringField,
    SubmitField,
    TextAreaField,
    FileField,
    SelectField,
)
from wtforms.validators import DataRequired  # type: ignore

from app.models import Category


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
