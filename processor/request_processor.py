from abc import ABC, abstractmethod

class PaymentProcessor(ABC):
    @abstractmethod
    async def request_payment(self, payment_data):
        """Initiate payment request to the gateway"""
        pass
