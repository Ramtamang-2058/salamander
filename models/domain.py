from models import DataModel
from datetime import datetime
from typing import Any
from dataclasses import dataclass
from abstracts import PaymentMethod, PaymentPlan
from models import DataModel


@dataclass
class PaymentData(DataModel):

    plan: PaymentPlan
    amount: float
    transaction_uuid : str
    payment_method: PaymentMethod
    data: Any = None

    def __init__(self, /, **data: Any) -> None:
        super().__init__(**data)

@dataclass
class PaymentRecord:
    user_id: str
    pidx: str
    purchase_order_id: str
    plan: str
    amount: int
    status: str
    payment_method: str
    created_at: datetime = datetime.utcnow()

    def __init__(self, /, **data: Any) -> None:
        super().__init__(**data)