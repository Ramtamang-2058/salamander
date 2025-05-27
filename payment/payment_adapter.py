import typing
from abc import ABC, abstractmethod

from models.domain import PaymentData


class PaymentAdapter(ABC):
    @abstractmethod
    def __verify_signature(self, data: typing.Any):
        pass

    @abstractmethod
    def __generate_signature(self, data: typing.Any):
        pass

    @abstractmethod
    def prepare_data(self, payment_data: PaymentData):
        pass