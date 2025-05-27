import base64
import hashlib
import hmac
import json
import typing

import requests

from config import ESEWA_SECRET_KEY, ESEWA_PRODUCT_CODE, BASE_URL, ESEWA_TRANS_VERIFY_URL
from database.db_handler import Payment
from database.db_handler import update_payment
from models.domain import PaymentData
from payment.handler import render_payment_success, render_payment_failure, apply_plan_to_user
from payment.payment_adapter import PaymentAdapter
from utils.logger import logger


class EsewaPaymentAdapter(PaymentAdapter):
    def __init__(self):
        self.ESEWA_SECRET_KEY = ESEWA_SECRET_KEY
        self.ESEWA_PRODUCT_CODE = ESEWA_PRODUCT_CODE

    def __generate_signature(self, data):
        amount_str = str(data["total_amount"])
        message = f"total_amount={amount_str},transaction_uuid={data['transaction_uuid']},product_code={data['product_code']}"
        logger.info(f"Signature message string: {message}")
        signature = hmac.new(
            data["secret_key"].encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        logger.info(f"Generated Signature: {signature_b64}")
        return signature_b64

    def __verify_signature(self, data: typing.Any):
        try:
            response_data = data.get('response_data')
            if not response_data:
                return False
            total_amount = response_data.get('total_amount', '')
            transaction_uuid = response_data.get('transaction_uuid', '')
            product_code = response_data.get('product_code', '')
            received_signature = response_data.get('signature', '')

            if not all([total_amount, transaction_uuid, product_code, received_signature]):
                logger.error(f"Missing required fields: total_amount={total_amount}, "
                             f"transaction_uuid={transaction_uuid}, product_code={product_code}, "
                             f"signature={received_signature}")
                return False

            # Normalize total_amount to match eSewa's expected format (integer string)
            total_amount_normalized = str(int(float(total_amount.replace(',', ''))))

            # Generate signature using the normalized total_amount
            generated_signature = self.__generate_signature(
                data={
                    'total_amount': total_amount_normalized,
                    'transaction_uuid': transaction_uuid,
                    'product_code': product_code,
                    'secret_key': data.get("secret_key"),
                }
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

    def prepare_data(self, payment_data: PaymentData):
        signature = self.__generate_signature(
            data={
                'total_amount': payment_data.amount,
                'transaction_uuid': payment_data.transaction_uuid,
                'product_code': ESEWA_PRODUCT_CODE,
                'secret_key': ESEWA_SECRET_KEY,
            }
        )
        return {
            'amount': str(payment_data.amount),
            'tax_amount': '0',
            'product_service_charge': '0',
            'product_delivery_charge': '0',
            'total_amount': str(payment_data.amount),
            'transaction_uuid': payment_data.transaction_uuid,
            'product_code': ESEWA_PRODUCT_CODE,
            'success_url': f'{BASE_URL}/payment/callback',
            'failure_url': f'{BASE_URL}/payment/failure',
            'signed_field_names': 'total_amount,transaction_uuid,product_code',
            'signature': signature
        }

    def __re_verify_payment(self, response_data, payment, payment_method: str) -> bool:
        if payment_method == 'esewa':
            try:
                total_amount = response_data.get('total_amount', '')
                amount = int(float(total_amount.replace(',', '')))
                transaction_uuid = response_data.get('transaction_uuid')
                return payment.amount == amount and transaction_uuid == payment.pidx
            except (ValueError, TypeError) as e:
                logger.error(f"Error parsing total_amount in eSewa verification: {e}")
                return False
        elif payment_method == 'khalti':
            return False

        logger.warning(f"Unsupported payment method: {payment_method}")
        return False

    def validate_signature(self, response_data: typing.Dict, payment: Payment):
        verify_signature = self.__verify_signature(
            data={'response_data': response_data})
        payment_verify = self.__re_verify_payment(
            response_data,
            payment_method='esewa',
            payment=payment,
        )
        if verify_signature or payment_verify:
            return True
        return False

    def __verify_esewa_status(self, payment):
        params = {
            'product_code': ESEWA_PRODUCT_CODE,
            'total_amount': str(payment.amount),
            'transaction_uuid': payment.pidx
        }

        try:
            response = requests.get(ESEWA_TRANS_VERIFY_URL, params=params)
            if response.status_code != 200:
                update_payment(payment.pidx, 'StatusCheckFailed')
                logger.warning(f"eSewa status check failed: {response.text}")
                return render_payment_failure("eSewa verification failed")

            data = response.json()
            logger.info(f"eSewa verification response: {data}")

            if data.get('status') == 'COMPLETE':
                update_payment(payment.pidx, 'Completed', data.get('ref_id'))
                apply_plan_to_user(payment)
                return render_payment_success("Payment successful! Your credits have been added.")
            else:
                update_payment(payment.pidx, f"Failed: {data.get('status')}")
                return render_payment_failure("eSewa verification failed")

        except Exception as e:
            logger.exception(f"eSewa status check error: {e}")
            update_payment(payment.pidx, 'StatusCheckError')
            return render_payment_failure("eSewa verification failed")

    def handle_esewa_callback(self, payment, encoded_response):
        if not encoded_response:
            logger.warning(f"Missing eSewa response for pidx={payment.pidx}")
            return render_payment_failure("Invalid payment response")

        try:
            decoded = base64.b64decode(encoded_response).decode('utf-8')
            response_data = json.loads(decoded)
            logger.info(f"Decoded eSewa response: {response_data}")

            esewa_adapter = EsewaPaymentAdapter()
            if not esewa_adapter.validate_signature(response_data, payment):
                update_payment(payment.pidx, 'SignatureInvalid')
                return render_payment_failure("Signature verification failed")

        except Exception as e:
            logger.exception(f"Error decoding eSewa response: {e}")
            return render_payment_failure("eSewa payment verification failed")

        return self.__verify_esewa_status(payment)
