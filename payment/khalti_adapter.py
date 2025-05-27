import requests
from flask import url_for, session

from config import KHALTI_BASE_URL, KHALTI_INITIATE_URL, KHALTI_LOOKUP_URL, KHALTI_SECRET_KEY
from database.db_handler import update_payment
from models.domain import PaymentData
from payment.helper import render_payment_success, render_payment_failure, apply_plan_to_user
from payment_adapter import PaymentAdapter
from utils.logger import logger


class KhaltiPaymentAdapter(PaymentAdapter):
    def __init__(self):
        self.KHALTI_BASE_URL = KHALTI_BASE_URL
        self.KHALTI_INITIATE_URL = KHALTI_INITIATE_URL
        self.KHALTI_SECRET_KEY = KHALTI_SECRET_KEY
        self.KHALTI_LOOKUP_URL = KHALTI_LOOKUP_URL

    def verify_signature(self):
        pass
    def generate_signature(self):
        pass


    def prepare_data(self, payment_data: PaymentData):
        amount = payment_data.amount
        transaction_uuid = payment_data.transaction_uuid
        plan = payment_data.plan.value  # Assuming it's from Enum

        payload = {
            'return_url': url_for('payment_callback', _external=True),
            'website_url': 'https://salamander.com',
            'amount': int(amount * 100),
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

        headers = {
            'Authorization': f'Key {KHALTI_SECRET_KEY}',
            'Content-Type': 'application/json'
        }

        return payload, headers

    def handle_khalti_callback(self, payment):
        try:
            headers = {'Authorization': f'Key {self.KHALTI_SECRET_KEY}', 'Content-Type': 'application/json'}
            payload = {'pidx': payment.pidx}
            response = requests.post(self.KHALTI_LOOKUP_URL, json=payload, headers=headers)
            data = response.json()

            if response.status_code == 200 and data.get('status') == 'Completed':
                update_payment(payment.pidx, 'Completed', data.get('transaction_id'))
                apply_plan_to_user(payment)
                logger.info(f"Khalti payment completed: pidx={payment.pidx}")
                return render_payment_success("Payment successful! Your credits have been added.")
            else:
                update_payment(payment.pidx, data.get('status', 'Failed'))
                logger.warning(f"Khalti verification failed: pidx={payment.pidx}")
                return render_payment_failure("Payment verification failed")
        except Exception as e:
            logger.exception(f"Khalti callback failed: {e}")
            update_payment(payment.pidx, 'VerificationFailed')
            return render_payment_failure("Khalti payment processing error")
