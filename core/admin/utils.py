from database.db_handler import db
from .models import AdminLog
from datetime import datetime

def log_admin_action(admin_id, action):
    """Log an admin action"""
    try:
        log = AdminLog(
            admin_id=admin_id,
            action=action
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging action: {str(e)}")