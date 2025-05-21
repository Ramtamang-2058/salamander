import base64
import functools
import hashlib
import hmac
import logging
import os
import uuid
import json
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from database.db_handler import db, Humanizer, User, Payment, save_user, save_humanizer, save_payment, update_payment

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure file handler for errors (don't show to users)
error_handler = logging.FileHandler('error.log')
error_handler.setLevel(logging.ERROR)
error_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
error_handler.setFormatter(error_formatter)
logger.addHandler(error_handler)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')

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
    # Normalize amount to integer string (remove decimals and commas)
    amount_str = str(total_amount)  # Handle commas and decimals
    message = f"total_amount={amount_str},transaction_uuid={transaction_uuid},product_code={product_code}"
    logger.info(f"Signature message string: {message}")
    signature = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    logger.info(f"Generated Signature: {signature_b64}")
    return signature_b64


def verify_esewa_signature(response_data, secret_key):
    """
    Verifies the signature received from eSewa by regenerating it using the same algorithm
    that was used to create the original signature.
    """
    try:
        # Extract essential fields
        total_amount = response_data.get('total_amount', '')
        transaction_uuid = response_data.get('transaction_uuid', '')
        product_code = response_data.get('product_code', '')
        received_signature = response_data.get('signature', '')

        # Check for missing fields
        if not all([total_amount, transaction_uuid, product_code, received_signature]):
            logger.error(f"Missing required fields: total_amount={total_amount}, "
                        f"transaction_uuid={transaction_uuid}, product_code={product_code}, "
                        f"signature={received_signature}")
            return False

        # Normalize total_amount to match eSewa's expected format (integer string)
        total_amount_normalized = str(int(float(total_amount.replace(',', ''))))

        # Generate signature using the normalized total_amount
        generated_signature = generate_esewa_signature(
            total_amount=total_amount_normalized,
            transaction_uuid=transaction_uuid,
            product_code=product_code,
            secret_key=secret_key
        )

        logger.info(f"Original signature: {received_signature}")
        logger.info(f"Generated signature: {generated_signature}")

        # Compare signatures
        is_valid = received_signature == generated_signature
        if not is_valid:
            logger.error(f"Signature mismatch: received={received_signature}, generated={generated_signature}")
        return is_valid

    except ValueError as ve:
        logger.error(f"Value error during signature verification: {ve}")
        return False
    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}", exc_info=True)
        return False


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
        return jsonify({"status": "error", "message": "Authentication failed"}), 500


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
        return jsonify({'error': 'Failed to process text'}), 500


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
            return jsonify({'error': 'Payment initiation failed'}), 400

        elif payment_method == 'esewa':
            signature = generate_esewa_signature(
                total_amount=amount,
                transaction_uuid=transaction_uuid,
                product_code=ESEWA_PRODUCT_CODE,
                secret_key=ESEWA_SECRET_KEY
            )
            esewa_params = {
                'amount': str(amount),
                'tax_amount': '0',
                'product_service_charge': '0',
                'product_delivery_charge': '0',
                'total_amount': str(amount),
                'transaction_uuid': transaction_uuid,
                'product_code': ESEWA_PRODUCT_CODE,
                'success_url': f'{BASE_URL}/payment/callback',
                'failure_url': f'{BASE_URL}/payment/failure',
                'signed_field_names': 'total_amount,transaction_uuid,product_code',
                'signature': signature
            }

            save_payment(
                user_id=session['user']['uid'],
                pidx=transaction_uuid,
                purchase_order_id=transaction_uuid,
                plan=plan,
                amount=amount,
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
        return jsonify({'error': 'Payment initiation failed'}), 500


@app.route('/payment/callback')
def payment_callback():
    try:
        pidx = request.args.get('pidx') or request.args.get('pid')
        encoded_response = request.args.get('data')  # eSewa-specific

        # For eSewa, extract transaction_uuid from data if pidx is missing
        if not pidx and encoded_response:
            try:
                decoded_response = base64.b64decode(encoded_response).decode('utf-8')
                response_data = json.loads(decoded_response)
                pidx = response_data.get('transaction_uuid')
                logger.info(f"Extracted pidx from eSewa data: {pidx}")
            except Exception as e:
                logger.error(f"Failed to decode eSewa data for pidx: {str(e)}")
                return render_template('payment_failure.html', message='Payment verification failed')

        if not pidx:
            logger.warning("Invalid callback parameters")
            return render_template('payment_failure.html', message='Invalid payment information')

        payment = Payment.query.filter_by(pidx=pidx).first()
        if not payment:
            logger.warning(f"Payment record not found: pidx={pidx}")
            return render_template('payment_failure.html', message='Payment record not found')

        if payment.user_id != session.get('user', {}).get('uid'):
            logger.warning(f"Unauthorized payment access: pidx={pidx}")
            return render_template('payment_failure.html', message='Unauthorized payment access')

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
                                       message='Payment verification failed')

        elif payment.payment_method == 'esewa':
            if not encoded_response:
                logger.warning(f"Missing eSewa response data: pidx={pidx}")
                return render_template('payment_failure.html', message='Invalid payment response')

            # Decode Base64 response
            try:
                decoded_response = base64.b64decode(encoded_response).decode('utf-8')
                response_data = json.loads(decoded_response)
                logger.info(f"eSewa callback response: {response_data}")

                # Verify signature
                is_valid = verify_esewa_signature(response_data, ESEWA_SECRET_KEY)

                if not is_valid:
                    logger.warning(f"eSewa signature verification failed: pidx={pidx}")
                    update_payment(pidx, 'SignatureInvalid')
                    return render_template('payment_failure.html', message='Payment verification failed')

            except Exception as e:
                logger.error(f"Failed to decode or verify eSewa response: {str(e)}")
                return render_template('payment_failure.html', message='Payment verification failed')

            # Verify transaction status with eSewa API
            params = {
                'product_code': ESEWA_PRODUCT_CODE,
                'total_amount': str(payment.amount),  # Ensure string format
                'transaction_uuid': pidx
            }

            try:
                response = requests.get(ESEWA_TRANS_VERIFY_URL, params=params)
                if response.status_code != 200:
                    logger.error(
                        f"eSewa status check failed: status_code={response.status_code}, response={response.text}")
                    update_payment(pidx, 'VerificationFailed')
                    return render_template('payment_failure.html', message='Payment verification failed')

                response_data_api = response.json()
                logger.info(f"eSewa status check response: {response_data_api}")

            except Exception as e:
                logger.error(f"eSewa status check request failed: {str(e)}")
                update_payment(pidx, 'StatusCheckFailed')
                return render_template('payment_failure.html', message='Payment verification failed')

            if response_data_api.get('status') == 'COMPLETE':
                try:
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
                        user.subscription_expiry = datetime.utcnow() + timedelta(
                            days=plan_details[plan]['validity_days'])
                        db.session.commit()

                        if 'user' in session:
                            session['user']['is_premium'] = user.is_premium

                        logger.info(
                            f"Updated user {user.uid}: word_credits={user.word_credits}, is_premium={user.is_premium}, expiry={user.subscription_expiry}")

                    logger.info(f"eSewa payment successful: pidx={pidx}")
                    return render_template('payment_success.html',
                                           message='Payment successful! Your credits have been added.')

                except Exception as e:
                    logger.error(f"Database update failed: {str(e)}")
                    db.session.rollback()
                    return render_template('payment_failure.html', message='Payment processing failed')
            else:
                status = response_data_api.get('status', 'Unknown')
                update_payment(pidx, f'Failed: {status}')
                logger.warning(f"eSewa verification failed: pidx={pidx}, status={status}")
                return render_template('payment_failure.html', message='Payment verification failed')

    except Exception as e:
        logger.error(f"Payment callback failed: {str(e)}", exc_info=True)
        if pidx:
            update_payment(pidx, 'CallbackError')
        return render_template('payment_failure.html', message='Payment processing failed')


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


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)