import os
import json
from datetime import datetime

from app import app, db
from app.models import Log


ALLOWED_EXTENSIONS = {"mp4", "avi", "mov"}


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def log_action(user_id, action):
    log_entry = Log(user_id=user_id, action=action)
    db.session.add(log_entry)
    db.session.commit()

    json_log = {
        "user_id": user_id,
        "action": action,
        "timestamp": datetime.utcnow().isoformat(),
    }

    log_file_path = os.path.join(app.root_path, "logs", "user_actions.json")
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
        else:
            logs = []

        logs.append(json_log)

        with open(log_file_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)

    except Exception as e:
        app.logger.error(f"Ошибка при сохранении лога в JSON: {e}")
