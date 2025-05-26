from datetime import datetime, timedelta

from database.db_handler import db, User, Payment, update_payment


class BillingService:
    def __init__(self):
        self.plan_details = {
            'basic': {'words': 10000, 'validity_days': 30, 'is_premium': False},
            'premium': {'words': 25000, 'validity_days': 60, 'is_premium': True},
            'pro': {'words': 60000, 'validity_days': 90, 'is_premium': True},
            'free': {'words': 1000, 'validity_days': 30, 'is_premium': False}
        }

    def can_use_service(self, user: User, word_count: int, ultra_mode: bool) -> bool:
        """Check if user can use the service based on plan, credits, and subscription status."""
        if not user:
            return False
        if ultra_mode and not user.is_premium:
            return False
        if user.subscription_expiry and user.subscription_expiry < datetime.utcnow():
            return False
        return user.word_credits >= word_count

    def process_successful_payment(self, payment: Payment, session: dict):
        """Update user credits and subscription after successful payment."""
        plan = payment.plan
        user = db.session.get(User, payment.user_id)
        if not user:
            raise ValueError("User not found")
        user.word_credits = (user.word_credits or 0) + self.plan_details[plan]['words']
        user.is_premium = self.plan_details[plan]['is_premium']
        user.subscription_expiry = datetime.utcnow() + timedelta(days=self.plan_details[plan]['validity_days'])
        update_payment(payment.pidx, 'Completed', payment.transaction_id)
        db.session.commit()
        if 'user' in session:
            session['user']['is_premium'] = user.is_premium
