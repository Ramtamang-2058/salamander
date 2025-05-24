import os
from payment_adapter import PaymentAdapter
from models.domain import PaymentData
from flask import url_for, session

# Payment gateway configurations
KHALTI_BASE_URL = os.environ.get('KHALTI_BASE_URL', 'https://dev.khalti.com/api/v2/')
KHALTI_INITIATE_URL = f'{KHALTI_BASE_URL}epayment/initiate/'
KHALTI_LOOKUP_URL = f'{KHALTI_BASE_URL}epayment/lookup/'
KHALTI_SECRET_KEY = os.environ.get('KHALTI_SECRET_KEY', 'test-secret-key')


class KhaltiPaymentAdapter(PaymentAdapter):
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