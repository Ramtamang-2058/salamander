import os
from payment_adapter import PaymentAdapter
from models.domain import PaymentData
from flask import url_for, session

# Payment gateway configurations

ESEWA_BASE_URL = os.environ.get('ESEWA_BASE_URL', 'https://rc-epay.esewa.com.np')
ESEWA_EPAY_URL = f'{ESEWA_BASE_URL}/api/epay/main/v2/form'
ESEWA_TRANS_VERIFY_URL = f'{ESEWA_BASE_URL}/api/epay/transaction/status/'
ESEWA_PRODUCT_CODE = os.environ.get('ESEWA_PRODUCT_CODE', 'EPAYTEST')
ESEWA_SECRET_KEY = os.environ.get('ESEWA_SECRET_KEY', '8gBm/:&EnhH.1/q')


class KhaltiPaymentAdapter(PaymentAdapter):
    def verify_signature(self):
        pass
    def generate_signature(self):
        pass


    def prepare_data(self, payment_data: PaymentData):
        amount = payment_data.amount
        transaction_uuid = payment_data.transaction_uuid
        plan = payment_data.plan.value  # Assuming it's from Enum

        if payment_method == 'esewa':
            signature = self.generate_signature(
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
        headers = {
            'Authorization': f'Key {KHALTI_SECRET_KEY}',
            'Content-Type': 'application/json'
        }

        return payload, headers