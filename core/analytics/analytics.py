# admin/analytics.py - Advanced analytics
from sqlalchemy import func, extract
from datetime import datetime, timedelta
from database.db_handler import User, Payment, Humanizer, ApiUsageLog, db


class Analytics:
    @staticmethod
    def get_user_growth_stats(days=30):
        """Get user growth statistics"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        growth_data = db.session.query(
            func.date(User.created_at).label('date'),
            func.count(User.uid).label('new_users')
        ).filter(
            User.created_at >= start_date
        ).group_by(
            func.date(User.created_at)
        ).order_by('date').all()

        return growth_data

    @staticmethod
    def get_revenue_stats(days=30):
        """Get revenue statistics"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        revenue_data = db.session.query(
            func.date(Payment.created_at).label('date'),
            func.sum(Payment.amount).label('revenue'),
            func.count(Payment.id).label('transactions')
        ).filter(
            Payment.created_at >= start_date,
            Payment.status == 'Completed'
        ).group_by(
            func.date(Payment.created_at)
        ).order_by('date').all()

        return revenue_data

    @staticmethod
    def get_usage_stats():
        """Get API usage statistics"""
        usage_stats = db.session.query(
            ApiUsageLog.endpoint,
            func.count(ApiUsageLog.id).label('requests'),
            func.sum(ApiUsageLog.credits_used).label('credits_used'),
            func.avg(ApiUsageLog.credits_used).label('avg_credits')
        ).group_by(ApiUsageLog.endpoint).all()

        return usage_stats

    @staticmethod
    def get_user_segments():
        """Get user segmentation data"""
        segments = {
            'total_users': User.query.count(),
            'premium_users': User.query.filter_by(is_premium=True).count(),
            'active_users': User.query.join(Humanizer).distinct().count(),
            'paying_users': User.query.join(Payment).filter_by(status='Completed').distinct().count()
        }