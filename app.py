import base64
import functools
import hashlib
import hmac
import logging
import os
import uuid
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from database.db_handler import db, Humanizer, User, Payment, save_user, save_humanizer, save_payment, update_payment

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

# Payment gateway configurations
KHALTI_BASE_URL = os.environ.get('KHALTI_BASE_URL', 'https://dev.khalti.com/api/v2/')
KHALTI_INITIATE_URL = f'{KHALTI_BASE_URL}epayment/initiate/'
KHALTI_LOOKUP_URL = f'{KHALTI_BASE_URL}epayment/lookup/'
KHALTI_SECRET_KEY = os.environ.get('KHALTI_SECRET_KEY', 'test-secret-key')

ESEWA_BASE_URL = os.environ.get('ESEWA_BASE_URL', 'https://rc-epay.esewa.com.np')
ESEWA_EPAY_URL = f'{ESEWA_BASE_URL}/api/epay/main/v2/form'
ESEWA_TRANS_VERIFY_URL = f'{ESEWA_BASE_URL}/api/epay/transaction/status/'
ESEWA_PRODUCT_CODE = os.environ.get('ESEWA_PRODUCT_CODE', 'EPAYTEST')
ESEWA_SECRET_KEY = os.environ.get('ESEWA_SECRET_KEY', '8gBm/:&EnhH.1/q')


# Placeholder for text processing
def paraphrase_text(text, ultra_mode=False):
    # Replace with actual implementation
    return f"Paraphrased: {text}"


# eSewa signature generation and verification
def generate_esewa_signature(total_amount, transaction_uuid, product_code, secret_key):
    message = f"total_amount={total_amount},transaction_uuid={transaction_uuid},product_code={product_code}"
    signature = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(signature).decode('utf-8')


def verify_esewa_signature(response_data, secret_key):
    signed_field_names = response_data.get('signed_field_names', '').split(',')
    message = ','.join(f"{field}={response_data[field]}" for field in signed_field_names)
    expected_signature = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(expected_signature).decode('utf-8') == response_data.get('signature')


# Middleware to check authentication
def login_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

@app.route('/')
def index():
    is_logged_in = 'user' in session
    user = db.session.get(User, session['user']['uid']) if is_logged_in else None
    if is_logged_in and user is None:
        session.clear()
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user, is_logged_in=is_logged_in)

@app.route('/login')
def login():
    return render_template('login.html', firebase_config=os.environ.get('FIREBASE_CONFIG', '{}'))

@app.route('/auth/google', methods=['POST'])
@csrf.exempt  # Adjust based on client implementation
def google_auth():
    try:
        id_token = request.json.get('idToken')
        # Placeholder for Firebase authentication
        user_info = {'uid': 'test-uid', 'name': 'Test User', 'email': 'test@example.com',
                     'picture': ''}  # Replace with google_sign_in(id_token)
        uid = user_info.get('uid')
        name = user_info.get('name')
        email = user_info.get('email') or 'human@gmail.com'
        picture = user_info.get('picture', '')
        user = save_user(uid, name, email, picture)
        if not user:
            return jsonify({"status": "error", "message": "Failed to save user"}), 500
        session['user'] = {
            'uid': user.uid,
            'name': user.name,
            'email': user.email,
            'picture': user.picture,
            'is_premium': user.is_premium
        }
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Google auth failed: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/purchase')
@login_required
def purchase():
    user = db.session.get(User, session['user']['uid'])
    return render_template('payment.html', user=user, is_logged_in=True)

@app.route('/api/humanize', methods=['POST'])
@login_required
@csrf.exempt  # Adjust based on client implementation
def humanize_text():
    try:
        data = request.get_json()
        text = data.get('text', '')
        ultra_mode = data.get('ultra_mode', False)
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        is_premium = session['user'].get('is_premium', False)
        if ultra_mode and not is_premium:
            return jsonify({'error': 'Ultra Mode requires a premium subscription'}), 403
        result = paraphrase_text(text, ultra_mode=ultra_mode and is_premium)
        save_humanizer(session['user']['uid'], text, result, ultra_mode=ultra_mode)
        return jsonify({
            'result': result,
            'stats': {
                'readability': 'Excellent' if ultra_mode else 'Good',
                'uniqueness': '97%' if ultra_mode else '85%',
            }
        })
    except Exception as e:
        logger.error(f"Humanize text failed: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500

@app.route('/api/payment/initiate', methods=['POST'])
@login_required
@csrf.exempt  # Adjust based on client implementation
def initiate_payment():
    try:
        data = request.get_json()
        plan = data.get('plan')
        amount = data.get('amount')
        payment_method = data.get('payment_method', 'esewa')

        # Validate plan and amount
        plan_details = {
            'basic': {'amount': 500, 'words': 10000, 'validity_days': 30, 'is_premium': False},
            'premium': {'amount': 1000, 'words': 25000, 'validity_days': 60, 'is_premium': True},
            'pro': {'amount': 2000, 'words': 60000, 'validity_days': 90, 'is_premium': True}
        }

        if plan not in plan_details or plan_details[plan]['amount'] != amount:
            logger.warning(f"Invalid plan or amount: plan={plan}, amount={amount}")
            return jsonify({'error': 'Invalid plan or amount'}), 400

        # Generate unique transaction UUID
        transaction_uuid = f"SALAMANDER_{uuid.uuid4().hex}"

        if payment_method == 'khalti':
            payload = {
                'return_url': url_for('payment_callback', _external=True),
                'website_url': 'https://salamander.com',
                'amount': amount * 100,  # Convert to paisa
                'purchase_order_id': transaction_uuid,
                'purchase_order_name': f"{plan.capitalize()} Plan",
                'customer_info': {
                    'name': session['user']['name'],
                    'email': session['user']['email'],
                    'phone': '9800000001'
                },
                'merchant_username': 'salamander',
                'merchant_extra': f"plan:{plan}"
            }
            headers = {'Authorization': f'Key {KHALTI_SECRET_KEY}', 'Content-Type': 'application/json'}
            response = requests.post(KHALTI_INITIATE_URL, json=payload, headers=headers)
            response_data = response.json()

            if response.status_code == 200 and 'pidx' in response_data:
                save_payment(
                    user_id=session['user']['uid'],
                    pidx=response_data['pidx'],
                    purchase_order_id=transaction_uuid,
                    plan=plan,
                    amount=amount * 100,
                    status='Initiated',
                    payment_method='khalti'
                )
                logger.info(f"Khalti payment initiated: pidx={response_data['pidx']}")
                return jsonify({'status': 'success', 'payment_url': response_data['payment_url']})
            logger.warning(f"Khalti initiation failed: {response_data.get('error_key')}")
            return jsonify({'error': response_data.get('error_key', 'Payment initiation failed')}), 400

        elif payment_method == 'esewa':
            esewa_params = {
                'amount': str(amount),
                'tax_amount': '0',
                'product_service_charge': '0',
                'product_delivery_charge': '0',
                'total_amount': str(amount),
                'transaction_uuid': transaction_uuid,
                'product_code': ESEWA_PRODUCT_CODE,
                'success_url': url_for('payment_callback', _external=True),
                'failure_url': url_for('payment_failure', _external=True),
                'signed_field_names': 'total_amount,transaction_uuid,product_code',
                'signature': generate_esewa_signature(amount, transaction_uuid, ESEWA_PRODUCT_CODE, ESEWA_SECRET_KEY)
            }
            save_payment(
                user_id=session['user']['uid'],
                pidx=transaction_uuid,
                purchase_order_id=transaction_uuid,
                plan=plan,
                amount=amount,  # Store in rupees
                status='Initiated',
                payment_method='esewa'
            )
            logger.info(f"eSewa payment initiated: transaction_uuid={transaction_uuid}")
            return jsonify({
                'status': 'success',
                'payment_url': ESEWA_EPAY_URL,
                'form_data': esewa_params,
                'method': 'POST'
            })

        logger.warning(f"Invalid payment method: {payment_method}")
        return jsonify({'error': 'Invalid payment method'}), 400

    except Exception as e:
        logger.error(f"Payment initiation failed: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/payment/callback')
def payment_callback():
    try:
        pidx = request.args.get('pidx') or request.args.get('pid')
        encoded_response = request.args.get('data')  # eSewa-specific

        if not pidx:
            logger.warning("Invalid callback parameters")
            return render_template('payment_failure.html', message='Invalid callback parameters')

        payment = Payment.query.filter_by(pidx=pidx).first()
        if not payment or payment.user_id != session['user']['uid']:
            logger.warning(f"Invalid or unauthorized payment: pidx={pidx}")
            return render_template('payment_failure.html', message='Invalid or unauthorized payment')

        if payment.status == 'Completed':
            logger.info(f"Payment already processed: pidx={pidx}")
            return render_template('payment_success.html', message='Payment already processed')

        if payment.payment_method == 'khalti':
            headers = {'Authorization': f'Key {KHALTI_SECRET_KEY}', 'Content-Type': 'application/json'}
            payload = {'pidx': pidx}
            response = requests.post(KHALTI_LOOKUP_URL, json=payload, headers=headers)
            lookup_data = response.json()

            if response.status_code == 200 and lookup_data['status'] == 'Completed':
                with db.session.begin():
                    update_payment(pidx, 'Completed', lookup_data.get('transaction_id'))
                    plan_details = {
                        'basic': {'words': 10000, 'validity_days': 30, 'is_premium': False},
                        'premium': {'words': 25000, 'validity_days': 60, 'is_premium': True},
                        'pro': {'words': 60000, 'validity_days': 90, 'is_premium': True}
                    }
                    plan = payment.plan
                    user = db.session.get(User, session['user']['uid'])
                    user.word_credits = (user.word_credits or 0) + plan_details[plan]['words']
                    user.is_premium = plan_details[plan]['is_premium']
                    user.subscription_expiry = datetime.utcnow() + timedelta(days=plan_details[plan]['validity_days'])
                    db.session.commit()
                    session['user']['is_premium'] = user.is_premium
                logger.info(f"Khalti payment successful: pidx={pidx}")
                return render_template('payment_success.html',
                                       message='Payment successful! Your credits have been added.')
            else:
                update_payment(pidx, lookup_data.get('status', 'Failed'))
                logger.warning(f"Khalti verification failed: pidx={pidx}, status={lookup_data.get('status')}")
                return render_template('payment_failure.html',
                                       message=f'Payment verification failed: {lookup_data.get("status", "Unknown error")}')

        elif payment.payment_method == 'esewa':
            if not encoded_response:
                logger.warning(f"Missing eSewa response data: pidx={pidx}")
                return render_template('payment_failure.html', message='Invalid eSewa response')

            # Decode Base64 response
            try:
                decoded_response = base64.b64decode(encoded_response).decode('utf-8')
                response_data = json.loads(decoded_response)
            except Exception as e:
                logger.error(f"Failed to decode eSewa response: {str(e)}")
                return render_template('payment_failure.html', message='Invalid response format')

            # Verify signature
            if not verify_esewa_signature(response_data, ESEWA_SECRET_KEY):
                logger.warning(f"eSewa signature verification failed: pidx={pidx}")
                update_payment(pidx, 'Failed')
                return render_template('payment_failure.html', message='Signature verification failed')

            # Verify transaction status
            params = {
                'product_code': ESEWA_PRODUCT_CODE,
                'total_amount': payment.amount,
                'transaction_uuid': pidx
            }
            response = requests.get(ESEWA_TRANS_VERIFY_URL, params=params)
            response_data_api = response.json()

            if response.status_code == 200 and response_data_api['status'] == 'COMPLETE':
                with db.session.begin():
                    update_payment(pidx, 'Completed', response_data_api.get('ref_id'))
                    plan_details = {
                        'basic': {'words': 10000, 'validity_days': 30, 'is_premium': False},
                        'premium': {'words': 25000, 'validity_days': 60, 'is_premium': True},
                        'pro': {'words': 60000, 'validity_days': 90, 'is_premium': True}
                    }
                    plan = payment.plan
                    user = db.session.get(User, session['user']['uid'])
                    user.word_credits = (user.word_credits or 0) + plan_details[plan]['words']
                    user.is_premium = plan_details[plan]['is_premium']
                    user.subscription_expiry = datetime.utcnow() + timedelta(days=plan_details[plan]['validity_days'])
                    db.session.commit()
                    session['user']['is_premium'] = user.is_premium
                logger.info(f"eSewa payment successful: pidx={pidx}")
                return render_template('payment_success.html',
                                       message='Payment successful! Your credits have been added.')
            else:
                update_payment(pidx, response_data_api.get('status', 'Failed'))
                logger.warning(f"eSewa verification failed: pidx={pidx}, status={response_data_api.get('status')}")
                return render_template('payment_failure.html',
                                       message=f'Payment verification failed: {response_data_api.get("status", "Unknown error")}')

    except Exception as e:
        logger.error(f"Payment callback failed: {str(e)}", exc_info=True)
        if pidx:
            update_payment(pidx, 'Failed')
        return render_template('payment_failure.html', message=str(e))


@app.route('/payment/failure')
def payment_failure():
    pidx = request.args.get('pid')
    if pidx:
        update_payment(pidx, 'Failed')
        logger.info(f"Payment failed or canceled: pidx={pidx}")
    return render_template('payment_failure.html', message='Payment failed or was canceled')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)