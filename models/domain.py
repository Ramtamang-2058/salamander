from dataclasses import dataclass
from datetime import datetime
from typing import Any

from models import DataModel


@dataclass
class PaymentData(DataModel):

    amount: float
    transaction_uuid : str
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