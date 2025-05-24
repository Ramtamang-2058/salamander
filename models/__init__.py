from typing import Dict

from pydantic import BaseModel


class BaseDict:

    def to_dict(self) -> Dict:
        def convert_value(value):
            if isinstance(value, BaseDict):
                return value.to_dict()
            elif isinstance(value, list):
                return [convert_value(item) for item in value]
            else:
                return value

        return {key: convert_value(value) for key, value in self.__dict__.items() if
                not key.startswith('__') and value is not None}

    def get(self, key, default=None):
        return getattr(self, key, default)

    def set(self, key, value):
        setattr(self, key, value)


class DataModel(BaseModel, BaseDict):
    """base model for form data"""

    class ConfigDict:
        frozen = False
        arbitrary_types_allowed = True
        extra = "ignore"
