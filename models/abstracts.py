from enum import Enum

plan_details = {
            'basic': {'amount': 500, 'words': 10000, 'validity_days': 30, 'is_premium': False},
            'premium': {'amount': 1000, 'words': 25000, 'validity_days': 60, 'is_premium': True},
            'pro': {'amount': 2000, 'words': 60000, 'validity_days': 90, 'is_premium': True}
        }

class PaymentMethod(Enum):
    ESEWA = "esewa"
    KHALTI = "khalti"


class PaymentPlan(Enum):
    BASIC = "basic"
    PREMIUM = "premium"
    PRO = "pro"
