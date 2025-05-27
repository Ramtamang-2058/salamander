import base64
import json

import requests
from flask import jsonify, session, url_for
from requests import request

from auth.firebase_auth import google_sign_in
from config import KHALTI_SECRET_KEY, SITE_ENDPOINT, KHALTI_INITIATE_URL, ESEWA_EPAY_URL
from database.db_handler import save_payment, save_user
from models.abstracts import plan_details
from models.domain import PaymentData
from payment.esewa_adapter import EsewaPaymentAdapter
from utils.logger import logger


def validate_plan(plan, amount):
    return plan in plan_details and plan_details[plan]['amount'] == amount


def handle_khalti_initiation(plan, amount, transaction_uuid):
    payload = {
        'return_url': url_for('payment_callback', _external=True),
        'website_url': SITE_ENDPOINT,
        'amount': amount * 100,
        'purchase_order_id': transaction_uuid,
        'purchase_order_name': f"{plan.capitalize()} Plan",
        'customer_info': {
            'name': session['user']['name'],
            'email': session['user']['email'],
            'phone': session['user'].get('phone', '9800000001')
        },
        'merchant_username': 'salamander',
        'merchant_extra': f"plan:{plan}"
    }
    headers = {
        'Authorization': f'Key {KHALTI_SECRET_KEY}',
        'Content-Type': 'application/json'
    }

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


def handle_esewa_initiation(plan, amount, transaction_uuid):
    esewa_adapter = EsewaPaymentAdapter()
    form_data = esewa_adapter.prepare_data(PaymentData(
        amount=amount,
        transaction_uuid=transaction_uuid,
        data=None
    ))

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
        'form_data': form_data,
        'method': 'POST'
    })



def extract_callback_identifiers():
    pidx = request.args.get('pidx') or request.args.get('pid')
    encoded_response = request.args.get('data')

    if not pidx and encoded_response:
        try:
            decoded = base64.b64decode(encoded_response).decode('utf-8')
            data = json.loads(decoded)
            pidx = data.get('transaction_uuid')
            logger.info(f"Extracted pidx from encoded response: {pidx}")
        except Exception as e:
            logger.error(f"Failed to extract pidx from encoded eSewa data: {e}")
            return None, encoded_response

    return pidx, encoded_response


def authenticate_and_set_session(id_token, token_source='Google'):
    if 'user' in session:
        return jsonify({
            'status': 'success',
            'message': 'You are already logged in.',
            'redirect': url_for('dashboard')
        }), 200

    try:
        user_data = google_sign_in(id_token)
        user = save_user(
            uid=user_data['uid'],
            name=user_data.get('name', 'User'),
            email=user_data.get('email', 'user@example.com'),
            # picture=user_data.get('picture', '')
        )
        if not user:
            return jsonify({
                'status': 'error',
                'message': f'Oops! Unable to save your data from {token_source}. Please try again later.'
            }), 500

        session['user'] = {
            'uid': user.uid,
            'idToken': id_token,
            'name': user.name,
            'email': user.email,
            'picture': user.picture,
            'is_premium': user.is_premium
        }
        return jsonify({
            'status': 'success',
            'message': f'Welcome back, {user.name}!',
            'redirect': url_for('dashboard')
        }), 200

    except Exception as e:
        logger.error(f"{token_source} authentication failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Authentication failed. Please check your credentials and try again.'
        }), 401
