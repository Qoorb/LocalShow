from flask import (
    render_template, redirect,
    url_for, request
)

from app.main import bp
from app.models import Video, Category


@bp.route("/")
def index():
    return redirect(url_for("main.browse_videos"))


@bp.route("/browse", methods=["GET"])
def browse_videos():
    page = request.args.get("page", 1, type=int)
    videos = Video.query.filter_by(
        hidden=False
    ).paginate(
        page=page, per_page=10
    )
    return render_template("main/browse_videos.html", videos=videos)


@bp.route("/filter", methods=["GET"])
def filter_videos():
    category_name = request.args.get("category")
    page = request.args.get("page", 1, type=int)
    query = Video.query.filter_by(hidden=False)
    categories = Category.query.all()

    if category_name:
        query = query.join(Video.category).filter(
            Category.name == category_name
        )

    videos = query.paginate(page=page, per_page=10)
    return render_template(
        "main/filter_videos.html",
        videos=videos,
        category=category_name,
        categories=categories,
    )
