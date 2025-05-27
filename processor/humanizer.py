import json
import logging

import httpx
from sqlalchemy.exc import SQLAlchemyError

from billing.sanitize import sanitize_input
from config import STEALTHGPT_API_URL, STEALTHGPT_API_TOKEN
from database.db_handler import ApiUsageLog
from database.db_handler import User, db

logger = logging.getLogger(__name__)

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

    async def paraphrase(self, text: str, user_id=None, ultra_mode=False):
        prompt = sanitize_input(text)
        return await self._make_request(prompt, user_id, rephrase=True, ultra_mode=ultra_mode)

    async def _make_request(self, prompt, user_id, rephrase=True, ultra_mode=False):
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

        async with httpx.AsyncClient(timeout=10) as client:
            try:
                response = await client.post(self.api_url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()

                credits_used = len(prompt.split()) * (2 if ultra_mode else 1)
                if user_id:
                    self._deduct_credits(user_id, credits_used)
                    self._log_usage(user_id, self.api_url, payload, data, credits_used)

                return data
            except httpx.HTTPError as e:
                logger.error(f"HTTP error: {str(e)}")
                return {"error": str(e)}

    def _deduct_credits(self, user_id, credits_used):
        try:
            user = db.session.get(User, user_id)
            if user:
                user.word_credits = max(user.word_credits - credits_used, 0)
                db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Credit deduction failed: {str(e)}")

    def _log_usage(self, user_id, endpoint, request_payload, response_payload, credits_used):
        try:
            log = ApiUsageLog(
                user_id=user_id,
                endpoint=endpoint,
                request_payload=json.dumps(request_payload),
                response_payload=json.dumps(response_payload),
                credits_used=credits_used
            )
            db.session.add(log)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Logging failed: {str(e)}")
