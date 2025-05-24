from abc import ABC, abstractmethod
from typing import Optional
from models.domain import PaymentData


class PaymentAdapter(ABC):
    @abstractmethod
    def verify_signature(self):
        pass

    @abstractmethod
    def generate_signature(self):
        pass

    @abstractmethod
    def prepare_data(self, payment_data: PaymentData):
        pass