# config.py
import os

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Firebase configuration
FIREBASE_CONFIG = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID"),
    "databaseURL": os.getenv("DATABASE_URL"),
}

# Path to Firebase service account key
FIREBASE_SERVICE_ACCOUNT_PATH = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH")

# Flask configuration
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

# Khalti configuration
KHALTI_SECRET_KEY = os.getenv("KHALTI_SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
ESEWA_SECRET_KEY = os.getenv("ESEWA_SECRET_KEY")
ESEWA_BASE_URL = os.environ.get("ESEWA_BASE_URL")
ESEWA_PRODUCT_CODE = os.environ.get("ESEWA_PRODUCT_CODE")
STEALTHGPT_API_TOKEN = os.getenv("STEALTHGPT_API_TOKEN", "static/ppt/")
STEALTHGPT_API_URL = os.getenv("STEALTHGPT_API_URL", "https://stealthgpt.ai/api/stealthify")
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')

# Payment gateway configurations
KHALTI_BASE_URL = os.environ.get('KHALTI_BASE_URL', 'https://dev.khalti.com/api/v2/')
KHALTI_INITIATE_URL = f'{KHALTI_BASE_URL}epayment/initiate/'
KHALTI_LOOKUP_URL = f'{KHALTI_BASE_URL}epayment/lookup/'

ESEWA_EPAY_URL = f'{ESEWA_BASE_URL}/api/epay/main/v2/form'
ESEWA_TRANS_VERIFY_URL = f'{ESEWA_BASE_URL}/api/epay/transaction/status/'
SITE_ENDPOINT = os.environ.get('SITE_ENDPOINT')
