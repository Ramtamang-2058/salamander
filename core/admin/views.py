from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from sqlalchemy import or_
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from core.admin.config import AdminConfig
from core.analytics.analytics import Analytics
from core.decorators import rate_limit, audit_log
from core.exports import DataExporter
from database.db_handler import User, Payment, Humanizer, ApiUsageLog
from database.db_handler import db
from .models import Admin, AdminLog

admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')


# Admin login required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please login to access the admin panel', 'error')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)

    return decorated_function


# Super admin required decorator
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session or session.get('admin_role') != 'super_admin':
            flash('Super admin access required', 'error')
            return redirect(url_for('admin.dashboard'))
        return f(*args, **kwargs)

    return decorated_function


@admin_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=AdminConfig.MAX_LOGIN_ATTEMPTS, window=AdminConfig.LOCKOUT_DURATION)
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        admin = Admin.query.filter_by(username=username, is_active=True).first()

        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            session['admin_role'] = admin.role
            session.permanent = True

            from .utils import log_admin_action
            log_admin_action(admin.id, 'Login')

            flash('Logged in successfully', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('admin/login.html')


@admin_bp.route('/logout')
@admin_required
def logout():
    admin_id = session.get('admin_id')
    from .utils import log_admin_action
    log_admin_action(admin_id, 'Logout')

    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin.login'))


@admin_bp.route('/')
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    stats = {
        'total_users': User.query.count(),
        'premium_users': User.query.filter_by(is_premium=True).count(),
        'total_payments': Payment.query.filter_by(status='Completed').count(),
        'total_humanizations': Humanizer.query.count(),
        'recent_registrations': User.query.order_by(User.created_at.desc()).limit(AdminConfig.RECENT_USERS_LIMIT).all()
    }

    user_growth = Analytics.get_user_growth_stats(AdminConfig.CHART_DAYS)
    payment_trends = Analytics.get_revenue_stats(AdminConfig.CHART_DAYS)
    recent_logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(AdminConfig.RECENT_LOGS_LIMIT).all()

    return render_template('admin/dashboard.html',
                           stats=stats,
                           user_growth=user_growth,
                           payment_trends=payment_trends,
                           recent_logs=recent_logs)


@admin_bp.route('/users')
@admin_required
def users():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = User.query
    if search:
        query = query.filter(or_(
            User.name.ilike(f'%{search}%'),
            User.email.ilike(f'%{search}%')
        ))

    users = query.order_by(User.created_at.desc()).paginate(
        page=page,
        per_page=AdminConfig.USERS_PER_PAGE,
        error_out=False
    )

    return render_template('admin/users.html', users=users, search=search)


@admin_bp.route('/user/<uid>')
@admin_required
def user_detail(uid):
    user = db.session.get(User, uid)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin.users'))

    humanizations = Humanizer.query.filter_by(user_id=uid).order_by(Humanizer.created_at.desc()).limit(5).all()
    payments = Payment.query.filter_by(user_id=uid).order_by(Payment.created_at.desc()).limit(5).all()
    api_usage = ApiUsageLog.query.filter_by(user_id=uid).order_by(ApiUsageLog.created_at.desc()).limit(5).all()

    return render_template('admin/user_detail.html',
                           user=user,
                           humanizations=humanizations,
                           payments=payments,
                           api_usage=api_usage)


@admin_bp.route('/user/<uid>/edit', methods=['GET', 'POST'])
@admin_required
@audit_log('Edit User')
def edit_user(uid):
    user = db.session.get(User, uid)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin.users'))

    if request.method == 'POST':
        try:
            user.name = request.form.get('name')
            user.email = request.form.get('email')
            user.word_credits = int(request.form.get('word_credits', user.word_credits))
            user.is_premium = request.form.get('is_premium') == 'true'

            expiry = request.form.get('subscription_expiry')
            if expiry:
                user.subscription_expiry = datetime.strptime(expiry, '%Y-%m-%d')
            elif user.subscription_expiry and request.form.get('is_premium') == 'false':
                user.subscription_expiry = None

            db.session.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('admin.user_detail', uid=uid))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')

    return render_template('admin/edit_user.html', user=user)


@admin_bp.route('/api/user/<uid>/toggle-premium', methods=['POST'])
@admin_required
@audit_log('Toggle Premium Status')
def toggle_premium(uid):
    user = db.session.get(User, uid)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    try:
        user.is_premium = not user.is_premium
        if user.is_premium:
            user.subscription_expiry = datetime.utcnow() + timedelta(days=30)
        else:
            user.subscription_expiry = None
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/payments')
@admin_required
def payments():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = Payment.query.join(User)
    if search:
        query = query.filter(or_(
            User.name.ilike(f'%{search}%'),
            User.email.ilike(f'%{search}%'),
            Payment.plan.ilike(f'%{search}%')
        ))

    payments = query.order_by(Payment.created_at.desc()).paginate(
        page=page,
        per_page=AdminConfig.PAYMENTS_PER_PAGE,
        error_out=False
    )

    return render_template('admin/payments.html', payments=payments, search=search)


@admin_bp.route('/export/payments')
@admin_required
@audit_log('Export Payments')
def export_payments():
    payments = Payment.query.all()
    return DataExporter.export_payments_csv(payments)


@admin_bp.route('/humanizations')
@admin_required
def humanizations():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = Humanizer.query.join(User)
    if search:
        query = query.filter(or_(
            User.name.ilike(f'%{search}%'),
            User.email.ilike(f'%{search}%'),
            Humanizer.input_text.ilike(f'%{search}%'),
            Humanizer.humanized_text.ilike(f'%{search}%')
        ))

    humanizations = query.order_by(Humanizer.created_at.desc()).paginate(
        page=page,
        per_page=AdminConfig.USERS_PER_PAGE,
        error_out=False
    )

    return render_template('admin/humanizations.html', humanizations=humanizations, search=search)


@admin_bp.route('/api_usage')
@admin_required
def api_usage():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = ApiUsageLog.query.outerjoin(User)
    if search:
        query = query.filter(or_(
            User.name.ilike(f'%{search}%'),
            User.email.ilike(f'%{search}%'),
            ApiUsageLog.endpoint.ilike(f'%{search}%')
        ))

    api_usage = query.order_by(ApiUsageLog.created_at.desc()).paginate(
        page=page,
        per_page=AdminConfig.USERS_PER_PAGE,
        error_out=False
    )

    return render_template('admin/api_usage.html', api_usage=api_usage, search=search)


@admin_bp.route('/logs')
@admin_required
def logs():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = AdminLog.query.join(Admin)
    if search:
        query = query.filter(or_(
            Admin.username.ilike(f'%{search}%'),
            Admin.email.ilike(f'%{search}%'),
            AdminLog.action.ilike(f'%{search}%')
        ))

    logs = query.order_by(AdminLog.created_at.desc()).paginate(
        page=page,
        per_page=AdminConfig.LOGS_PER_PAGE,
        error_out=False
    )

    return render_template('admin/logs.html', logs=logs, search=search)


@admin_bp.route('/admin_users')
@super_admin_required
def admin_users():
    admins = Admin.query.order_by(Admin.username).all()
    return render_template('admin/admin_users.html', admins=admins)


@admin_bp.route('/admin_users/create', methods=['GET', 'POST'])
@super_admin_required
@audit_log('Create Admin')
def create_admin():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')

            existing_admin = Admin.query.filter(
                or_(Admin.username == username, Admin.email == email)
            ).first()

            if existing_admin:
                flash('Username or email already exists', 'error')
                return redirect(url_for('admin.create_admin'))

            admin = Admin(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=role,
                is_active=True
            )

            db.session.add(admin)
            db.session.commit()
            flash('Admin created successfully', 'success')
            return redirect(url_for('admin.admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating admin: {str(e)}', 'error')

    return render_template('admin/create_admin.html')


@admin_bp.route('/admin_users/<int:admin_id>/edit', methods=['GET', 'POST'])
@super_admin_required
@audit_log('Edit Admin')
def edit_admin(admin_id):
    admin = db.session.get(Admin, admin_id)
    if not admin:
        flash('Admin not found', 'error')
        return redirect(url_for('admin.admin_users'))

    if request.method == 'POST':
        try:
            admin.username = request.form.get('username')
            admin.email = request.form.get('email')
            admin.role = request.form.get('role')
            admin.is_active = request.form.get('is_active') == 'true'

            password = request.form.get('password')
            if password:
                admin.password_hash = generate_password_hash(password)

            db.session.commit()
            flash('Admin updated successfully', 'success')
            return redirect(url_for('admin.admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating admin: {str(e)}', 'error')

    return render_template('admin/edit_admin.html', admin=admin)


@admin_bp.route('/api/admin/<int:admin_id>/delete', methods=['POST'])
@super_admin_required
@audit_log('Delete Admin')
def delete_admin(admin_id):
    admin = db.session.get(Admin, admin_id)
    if not admin:
        return jsonify({'success': False, 'error': 'Admin not found'}), 404

    if admin.role == 'super_admin':
        return jsonify({'success': False, 'error': 'Cannot delete super admin'}), 403

    try:
        db.session.delete(admin)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/settings', methods=['GET', 'POST'])
@admin_required
@audit_log('Update Settings')
def settings():
    settings = {
        'site_name': 'Admin Panel',
        'users_per_page': AdminConfig.USERS_PER_PAGE,
        'session_timeout': AdminConfig.SESSION_TIMEOUT
    }

    if request.method == 'POST':
        try:
            settings['site_name'] = request.form.get('site_name')
            settings['users_per_page'] = int(request.form.get('users_per_page'))
            settings['session_timeout'] = int(request.form.get('session_timeout'))

            # Update config (in a real implementation, save to database or config file)
            AdminConfig.USERS_PER_PAGE = settings['users_per_page']
            AdminConfig.SESSION_TIMEOUT = settings['session_timeout']

            flash('Settings updated successfully', 'success')
            return redirect(url_for('admin.settings'))
        except Exception as e:
            flash(f'Error updating settings: {str(e)}', 'error')

    return render_template('admin/settings.html', settings=settings)