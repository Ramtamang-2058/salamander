# admin/decorators.py - Additional security decorators
from functools import wraps
from flask import session, request, abort
from datetime import datetime, timedelta
import redis
import hashlib


# Optional: Redis for rate limiting (install redis-py if using)
# redis_client = redis.Redis(host='localhost', port=6379, db=0)

def rate_limit(max_requests=100, window=3600):
    """Rate limiting decorator"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory rate limiting (use Redis for production)
            client_ip = request.remote_addr
            key = f"rate_limit:{client_ip}"

            # For production, implement proper rate limiting with Redis
            # For now, just proceed
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def audit_log(action_type):
    """Decorator to automatically log admin actions"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from core.admin.utils import log_admin_action

            admin_id = session.get('admin_id')
            if admin_id:
                # Log the action before execution
                log_admin_action(admin_id, f"{action_type} - {f.__name__}")

            return f(*args, **kwargs)

        return decorated_function

    return decorator