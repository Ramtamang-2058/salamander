from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_migrate import Migrate
from auth.firebase_auth import google_sign_in
from config import FLASK_SECRET_KEY, FIREBASE_CONFIG, KHALTI_SECRET_KEY
from database.db_handler import db, save_user, save_humanizer, User, Humanizer, Payment, save_payment, update_payment
from processor.humanizer import paraphrase_text
import functools
import requests
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 7  # 1 week
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)

# Khalti API endpoints
KHALTI_BASE_URL = 'https://dev.khalti.com/api/v2/'  # Use 'https://khalti.com/api/v2/' for production
KHALTI_INITIATE_URL = f'{KHALTI_BASE_URL}epayment/initiate/'
KHALTI_LOOKUP_URL = f'{KHALTI_BASE_URL}epayment/lookup/'

# Make session permanent by default
@app.before_request
def make_session_permanent():
    session.permanent = True

# Middleware to check if user is authenticated
def login_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

@app.route('/')
def index():
    if 'user' in session:
        user = db.session.get(User, session['user']['uid'])
        if user is None:
            session.clear()
            return redirect(url_for('login'))
        return render_template('dashboard.html', user=user, is_logged_in=True)
    return render_template('dashboard.html', is_logged_in=False)

@app.route('/login')
def login():
    return render_template('login.html', firebase_config=FIREBASE_CONFIG)

@app.route('/auth/google', methods=['POST'])
def google_auth():
    id_token = request.json.get('idToken')
    user_info = google_sign_in(id_token)
    if user_info:
        try:
            uid = user_info.get('uid')
            name = user_info.get('name')
            email = user_info.get('email') or 'human@gmail.com'
            picture = user_info.get('picture', '')
            user = save_user(uid, name, email)

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
            return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "error", "message": "Invalid token"}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/purchase')
@login_required
def purchase():
    user = db.session.get(User, session['user']['uid'])
    return render_template('purchase.html', user=user, is_logged_in=True)

@app.route('/api/humanize', methods=['POST'])
@login_required
def humanize_text():
    data = request.get_json()
    text = data.get('text', '')
    ultra_mode = data.get('ultra_mode', False)
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    try:
        is_premium = session['user'].get('is_premium', False)
        if ultra_mode and not is_premium:
            return jsonify({'error': 'Ultra Mode requires a premium subscription'}), 403
        result = paraphrase_text(text, ultra_mode=ultra_mode and is_premium)
        save_humanizer(
            session['user']['uid'],
            text,
            result,
            ultra_mode=ultra_mode
        )
        return jsonify({
            'result': result,
            'stats': {
                'readability': 'Excellent' if ultra_mode else 'Good',
                'uniqueness': '97%' if ultra_mode else '85%',
            }
        })
    except Exception as e:
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
                'ultra_mode': False,
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<int:humanizer_id>', methods=['DELETE'])
@login_required
def delete_history(humanizer_id):
    try:
        humanizer = db.session.get(Humanizer, humanizer_id)
        if not humanizer or humanizer.user_id != session['user']['uid']:
            return jsonify({'error': 'History item not found or unauthorized'}), 404
        db.session.delete(humanizer)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/payment/initiate', methods=['POST'])
@login_required
def initiate_payment():
    try:
        data = request.get_json()
        plan = data.get('plan')
        amount = data.get('amount')  # Amount in NPR

        # Validate plan and amount
        plan_details = {
            'basic': {'amount': 500, 'words': 10000, 'validity_days': 30, 'is_premium': False},
            'premium': {'amount': 1000, 'words': 25000, 'validity_days': 60, 'is_premium': True},
            'pro': {'amount': 2000, 'words': 60000, 'validity_days': 90, 'is_premium': True}
        }

        if plan not in plan_details or plan_details[plan]['amount'] != amount:
            return jsonify({'error': 'Invalid plan or amount'}), 400

        # Generate unique purchase order ID
        purchase_order_id = f"SALAMANDER_{uuid.uuid4().hex}"

        # Prepare Khalti payment payload
        payload = {
            'return_url': url_for('payment_callback', _external=True),
            'website_url': 'https://salamander.com',  # Replace with your website URL
            'amount': amount * 100,  # Convert to paisa
            'purchase_order_id': purchase_order_id,
            'purchase_order_name': f"{plan.capitalize()} Plan",
            'customer_info': {
                'name': session['user']['name'],
                'email': session['user']['email'],
                'phone': '9800000001'  # Replace with actual user phone or placeholder
            },
            'merchant_username': 'salamander',
            'merchant_extra': f"plan:{plan}"
        }

        headers = {
            'Authorization': f'Key {KHALTI_SECRET_KEY}',
            'Content-Type': 'application/json'
        }

        # Initiate payment with Khalti
        response = requests.post(KHALTI_INITIATE_URL, json=payload, headers=headers)
        response_data = response.json()

        if response.status_code == 200 and 'pidx' in response_data:
            # Save payment record
            save_payment(
                user_id=session['user']['uid'],
                pidx=response_data['pidx'],
                purchase_order_id=purchase_order_id,
                plan=plan,
                amount=amount * 100,  # Store in paisa
                status='Initiated'
            )
            return jsonify({
                'status': 'success',
                'payment_url': response_data['payment_url']
            })
        else:
            return jsonify({'error': response_data.get('error_key', 'Payment initiation failed')}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/payment/callback')
def payment_callback():
    try:
        pidx = request.args.get('pidx')
        status = request.args.get('status')
        transaction_id = request.args.get('transaction_id')

        if not pidx or not status:
            return render_template('payment_failure.html', message='Invalid callback parameters')

        # Check if payment already processed
        payment = Payment.query.filter_by(pidx=pidx).first()
        if not payment or payment.user_id != session['user']['uid']:
            return render_template('payment_failure.html', message='Invalid or unauthorized payment')
        if payment.status == 'Completed':
            return render_template('payment_success.html', message='Payment already processed')

        # Verify payment with Khalti
        headers = {
            'Authorization': f'Key {KHALTI_SECRET_KEY}',
            'Content-Type': 'application/json'
        }
        payload = {'pidx': pidx}
        response = requests.post(KHALTI_LOOKUP_URL, json=payload, headers=headers)
        lookup_data = response.json()

        if response.status_code == 200 and lookup_data['status'] == 'Completed':
            # Update payment record
            update_payment(pidx, 'Completed', transaction_id)

            # Update user account
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

            # Update session
            session['user']['is_premium'] = user.is_premium

            return render_template('payment_success.html', message='Payment successful! Your credits have been added.')
        else:
            update_payment(pidx, lookup_data.get('status', 'Failed'))
            return render_template('payment_failure.html', message=f'Payment verification failed: {lookup_data.get("status", "Unknown error")}')

    except Exception as e:
        if pidx:
            update_payment(pidx, 'Failed')
        return render_template('payment_failure.html', message=str(e))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)