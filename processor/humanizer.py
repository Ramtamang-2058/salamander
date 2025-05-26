import json
import time

import requests

from utils.logger import logger
from billing.sanitize import sanitize_input
from config import STEALTHGPT_API_TOKEN, STEALTHGPT_API_URL
from database.db_handler import ApiUsageLog
from database.db_handler import db, User


def paraphrase_text(text, ultra_mode=False):
    """
    Paraphrase the input text.

    This is a simple implementation. In a real application, you would use
    an NLP model or API like GPT, T5, or other language models.
    """
    # Add a small delay to simulate processing time
    time.sleep(0.2)

    # Simple word replacements for demonstration
    # In a real implementation, you would use a proper NLP model
    replacements = {
        "good": "excellent",
        "bad": "poor",
        "big": "large",
        "small": "tiny",
        "happy": "joyful",
        "sad": "unhappy",
        "smart": "intelligent",
        "fast": "quick",
        "slow": "gradual",
        "important": "essential",
        "difficult": "challenging",
        "easy": "simple",
        "beautiful": "gorgeous",
        "ugly": "unattractive",
        "old": "aged",
        "new": "recent",
        "expensive": "costly",
        "cheap": "inexpensive",
        "interesting": "fascinating",
        "boring": "dull",
    }

    words = text.split()

    for i, word in enumerate(words):
        clean_word = word.lower().strip('.,!?;:()"\'')
        if clean_word in replacements:
            # Keep the original capitalization and punctuation
            punctuation = ''
            if not word[-1].isalnum():
                punctuation = word[-1]

            replacement = replacements[clean_word]

            if word[0].isupper():
                replacement = replacement.capitalize()

            words[i] = replacement + punctuation

    return ' '.join(words)


class StealthGPTClient:
    def __init__(self, tone='College', mode='Medium', business=False, multilingual=True):
        self.api_url = STEALTHGPT_API_URL
        self.api_token = STEALTHGPT_API_TOKEN
        self.default_payload = {
            'tone': tone,
            'mode': mode,
            'business': business,
            'isMultilingual': multilingual
        }

    def paraphrase(self, text: str, user_id: str = None, ultra_mode: bool = False) -> dict:
        """Paraphrase text with optional user ID and ultra mode."""
        sanitized_text = sanitize_input(text)
        return self._make_request(sanitized_text, user_id, rephrase=True, ultra_mode=ultra_mode)

    def generate(self, prompt: str, user_id: str = None) -> dict:
        """Generate text with optional user ID."""
        sanitized_prompt = sanitize_input(prompt)
        return self._make_request(sanitized_prompt, user_id, rephrase=False)

    @staticmethod
    def _log_usage(user_id: str, endpoint: str, request_payload: dict, response_payload: dict, credits_used: int):
        """Log API usage to the database."""
        log = ApiUsageLog(
            user_id=user_id,
            endpoint=endpoint,
            request_payload=json.dumps(request_payload),
            response_payload=json.dumps(response_payload),
            credits_used=credits_used,
        )
        db.session.add(log)
        db.session.commit()

    @staticmethod
    def _deduct_credits(user_id: str, credits_used: int):
        """Deduct word credits from user."""
        user = db.session.get(User, user_id)
        if user:
            user.word_credits = max(user.word_credits - credits_used, 0)
            db.session.commit()

    def _make_request(self, prompt: str, user_id: str = None, rephrase: bool = True, ultra_mode: bool = False) -> dict:
        """Make API request to StealthGPT."""
        headers = {
            'api-token': self.api_token,
            'Content-Type': 'application/json'
        }
        payload = {
            **self.default_payload,
            'prompt': prompt,
            'rephrase': rephrase,
            'ultra_mode': ultra_mode
        }
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            response_data = response.json()
            credits_used = len(prompt.split()) * (2 if ultra_mode else 1)
            if user_id:
                self._deduct_credits(user_id, credits_used)
                self._log_usage(user_id, self.api_url, payload, response_data, credits_used)
            return response_data
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return {"error": str(e)}
