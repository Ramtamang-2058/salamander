from datetime import datetime, timedelta

from flask import render_template

from models.abstracts import plan_details


def apply_plan_to_user(user, plan_key):
    details = plan_details[plan_key]
    user.word_credits = (user.word_credits or 0) + details['words']
    user.is_premium = details['is_premium']
    user.subscription_expiry = datetime.utcnow() + timedelta(days=details['validity_days'])


def render_payment_failure(message):
    return render_template('payment_failure.html', message=message)


def render_payment_success(message):
    return render_template('payment_success.html', message=message)
