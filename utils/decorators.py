import functools

from flask import session, redirect, url_for


# Middleware to check authentication
def login_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return wrap
