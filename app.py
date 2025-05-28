import asyncio
import os
import uuid
from datetime import datetime, timedelta

from flask import Blueprint, Flask, render_template, request, jsonify, session, redirect, url_for
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from auth.firebase_auth import AuthService
from billing.billing_service import BillingService
from billing.rate_limiter import RateLimiter
from config import (
    SQLALCHEMY_DATABASE_URI,
    FIREBASE_CONFIG
)
from core.admin.cli import register_admin_commands
from core.admin.views import admin_bp
from database.db_handler import db, Humanizer, User, Payment, save_humanizer, update_payment
from payment.esewa_adapter import EsewaPaymentAdapter
from payment.handler import (
    render_payment_success,
    render_payment_failure,
)
from payment.helper import (
    extract_callback_identifiers,
    authenticate_and_set_session,
)
from payment.helper import handle_esewa_initiation, handle_khalti_initiation, validate_plan
from payment.khalti_adapter import KhaltiPaymentAdapter
from processor.humanizer import StealthGPTClient
from utils.decorators import login_required
from utils.logger import logger

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
app.register_blueprint(admin_bp, url_prefix='/admin')

client = StealthGPTClient()
# Register CLI commands
register_admin_commands(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
payment_bp = Blueprint('payment', __name__)


billing_service = BillingService()
auth_service = AuthService()
rate_limiter = RateLimiter(max_requests=3, window_seconds=86400)

# test


@app.route('/health')
def health_check():
    """Health check endpoint for deployment verification"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {}
    }

    # Test database connection
    try:
        from sqlalchemy import text
        if 'db' in globals():
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            health_status["services"]["database"] = "healthy"
        else:
            health_status["services"]["database"] = "not configured"
    except Exception as e:
        health_status["services"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"

    # Test Firebase connection
    try:
        from auth.firebase_auth import firebase_admin
        if firebase_admin._apps:
            health_status["services"]["firebase"] = "healthy"
        else:
            health_status["services"]["firebase"] = "not initialized"
            health_status["status"] = "degraded"
    except Exception as e:
        health_status["services"]["firebase"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"

    # Check environment variables
    required_env_vars = ['FIREBASE_PROJECT_ID', 'FLASK_SECRET_KEY']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]

    if missing_vars:
        health_status["services"]["environment"] = f"missing variables: {missing_vars}"
        health_status["status"] = "degraded"
    else:
        health_status["services"]["environment"] = "healthy"

    # Return appropriate HTTP status code
    status_code = 200 if health_status["status"] == "healthy" else 503

    return health_status, status_code

@app.route('/', endpoint='dashboard')
def index():
    is_logged_in = 'user' in session
    user = db.session.get(User, session['user']['uid']) if is_logged_in else None
    if is_logged_in and user is None:
        session.clear()
        return redirect(url_for('login'))
    return render_template('dashboard.html',
                           user=user,
                           is_logged_in=is_logged_in,
                           firebase_config=FIREBASE_CONFIG)


@app.route('/login')
def login():
    return render_template('login.html', firebase_config=FIREBASE_CONFIG)


@app.route('/auth/google', methods=['POST'])
def google_auth():
    id_token = request.json.get('idToken')
    return authenticate_and_set_session(id_token, token_source='Google')


@app.route('/set_session', methods=['POST'])
def set_session():
    id_token = request.form.get('id_token')
    return authenticate_and_set_session(id_token, token_source='Session')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/purchase')
@login_required
def purchase():
    user = db.session.get(User, session['user']['uid'])
    return render_template('payment.html', user=user, is_logged_in=True)


@app.route('/api/user', methods=['GET'])
@login_required
def get_user():
    user = db.session.get(User, session['user']['uid'])
    return jsonify({
        'word_credits': user.word_credits,
        'is_premium': user.is_premium
    })


@app.route('/api/humanize', methods=['POST'])
def humanize_text():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON payload'}), 400

        text = data.get('text', '').strip()
        ultra_mode = data.get('ultra_mode', False)
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        if len(text) > 10000:
            return jsonify({'error': 'Text exceeds 10,000 character limit'}), 400

        user_id = session.get('user', {}).get('uid')
        ip_address = request.remote_addr
        word_count = len(text.split())

        async def handle_request():
            if user_id:
                user = db.session.get(User, user_id)
                if not user:
                    return {'error': 'User not found'}, 404
                if ultra_mode and not user.is_premium:
                    return {'error': 'Ultra mode requires premium'}, 403
                if not user.is_premium and user.subscription_expiry and user.subscription_expiry < datetime.utcnow():
                    return {'error': 'Subscription expired'}, 403
                if not user.is_premium and user.word_credits < word_count:
                    return {'error': 'Insufficient credits'}, 403

                result = await client.paraphrase(text, user_id=user_id, ultra_mode=ultra_mode)
                if 'error' in result:
                    return {'error': result['error']}, 500

                save_humanizer(user_id, text, result.get('response', ''), ultra_mode=ultra_mode)

                return {
                    'result': result.get('response'),
                    'stats': {'readability': 'Excellent' if ultra_mode else 'Good'}
                }, 200

            else:
                if ultra_mode:
                    return {'error': 'Login required for Ultra mode'}, 403
                if word_count > 100:
                    return {'error': 'Free version limited to 100 words'}, 400
                if not rate_limiter.allow_request(ip_address):
                    return {'error': 'Rate limit exceeded'}, 429

                result = await client.paraphrase(text, ultra_mode=False)
                if 'error' in result:
                    return {'error': result['error']}, 500

                return {
                    'result': result.get('response'),
                    'stats': {'readability': 'Good'}
                }, 200

        # Run async block from sync route
        result, status = asyncio.run(handle_request())
        return jsonify(result), status

    except Exception as e:
        logger.error(f"Humanize failed: {e}", exc_info=True)
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search_query = request.args.get('search', '', type=str)
        query = Humanizer.query.filter_by(user_id=session['user']['uid'])
        if search_query:
            query = query.filter(Humanizer.input_text.ilike(f'%{search_query}%'))
        humanizers = query.order_by(Humanizer.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        history = [
            {
                'id': h.id,
                'title': h.input_text[:50] + '...' if len(h.input_text) > 50 else h.input_text,
                'humanized_text': h.humanized_text,
                'ultra_mode': h.ultra_mode,
                'created_at': h.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'word_count': len(h.input_text.split())
            }
            for h in humanizers.items
        ]
        return jsonify({
            'history': history,
            'total': humanizers.total,
            'pages': humanizers.pages,
            'current_page': humanizers.page
        })
    except Exception as e:
        logger.error(f"Get history failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve history'}), 500


@app.route('/api/history/<int:humanizer_id>', methods=['DELETE'])
@login_required
@csrf.exempt  # Adjust based on client implementation
def delete_history(humanizer_id):
    try:
        with db.session.begin():
            humanizer = db.session.get(Humanizer, humanizer_id)
            if not humanizer or humanizer.user_id != session['user']['uid']:
                return jsonify({'error': 'History item not found or unauthorized'}), 404
            db.session.delete(humanizer)
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Delete history failed: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': 'Failed to delete history item'}), 500

@app.route('/api/history/clear', methods=['DELETE'])
@login_required
@csrf.exempt
def clear_history():
    try:
        with db.session.begin():
            Humanizer.query.filter_by(user_id=session['user']['uid']).delete()
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Clear history failed: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': 'Failed to clear history'}), 500


@app.route('/api/payment/initiate', methods=['POST'])
@login_required
@csrf.exempt
def initiate_payment():
    try:
        data = request.get_json()
        plan = data.get('plan')
        amount = data.get('amount')
        payment_method = data.get('payment_method', 'esewa')

        if not validate_plan(plan, amount):
            logger.warning(f"Invalid plan or amount: plan={plan}, amount={amount}")
            return jsonify({'error': 'Invalid plan or amount'}), 400

        transaction_uuid = f"SALAMANDER_{uuid.uuid4().hex}"

        if payment_method == 'khalti':
            return handle_khalti_initiation(plan, amount, transaction_uuid)

        elif payment_method == 'esewa':
            return handle_esewa_initiation(plan, amount, transaction_uuid)

        logger.warning(f"Invalid payment method: {payment_method}")
        return jsonify({'error': 'Invalid payment method'}), 400

    except Exception as e:
        logger.error(f"Payment initiation failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'Payment initiation failed'}), 500



@app.route('/payment/callback')
def payment_callback():
    try:

        pidx, encoded_response = extract_callback_identifiers()

        if not pidx:
            logger.warning("Missing payment identifier (pidx)")
            return render_payment_failure("Invalid payment information")

        payment = Payment.query.filter_by(pidx=pidx).first()
        if not payment:
            logger.warning(f"Payment record not found for pidx={pidx}")
            return render_payment_failure("Payment record not found")

        if not is_authorized_user(payment.user_id):
            logger.warning(f"Unauthorized access attempt: pidx={pidx}")
            return render_payment_failure("Unauthorized payment access")

        if payment.status == 'Completed':
            logger.info(f"Duplicate callback for completed payment: pidx={pidx}")
            return render_payment_success("Payment already processed")

        if payment.payment_method == 'khalti':
            khalti_adapter = KhaltiPaymentAdapter()
            return khalti_adapter.handle_khalti_callback(payment)

        elif payment.payment_method == 'esewa':
            esewa_adapter = EsewaPaymentAdapter()
            return esewa_adapter.handle_esewa_callback(payment, encoded_response)

        logger.warning(f"Unsupported payment method: {payment.payment_method}")
        return render_payment_failure("Unsupported payment method")

    except Exception as e:
        logger.exception(f"Unhandled exception in payment_callback: {e}")
        if 'pidx' in locals():
            update_payment(pidx, 'CallbackError')
        return render_payment_failure("Payment processing failed")


@app.route('/payment/failure')
def payment_failure():
    pidx = request.args.get('pid')
    if pidx:
        update_payment(pidx, 'Failed')
        logger.info(f"Payment failed or canceled: pidx={pidx}")
    return render_template('payment_failure.html', message='Payment failed or was canceled')


# Error handlers to prevent exposing technical details to users
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message='Page not found', status_code=404), 404


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template('error.html', message='An internal error occurred', status_code=500), 500


@app.errorhandler(403)
def forbidden_error(e):
    return render_template('error.html', message='Access denied', status_code=403), 403


@app.errorhandler(400)
def bad_request_error(e):
    return render_template('error.html', message='Bad request', status_code=400), 400


@app.teardown_request
def teardown_request(exception=None):
    try:
        if exception:
            db.session.rollback()
        else:
            db.session.commit()
    finally:
        db.session.remove()


if __name__ == '__main__':
    app.run(debug=True)