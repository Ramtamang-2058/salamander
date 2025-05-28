# auth/firebase_auth.py - Final version with robust error handling

import os
import json
import firebase_admin
import pyrebase
from firebase_admin import credentials, auth


def get_firebase_credentials():
    """Get Firebase credentials with multiple fallback options"""

    # Option 1: Try environment variable (preferred for production)
    firebase_config_str = os.getenv('FIREBASE_CONFIG')
    if firebase_config_str:
        try:
            config_dict = json.loads(firebase_config_str)
            print("✅ Using Firebase config from environment variable")
            return credentials.Certificate(config_dict)
        except json.JSONDecodeError as e:
            print(f"❌ Error parsing FIREBASE_CONFIG environment variable: {e}")

    # Option 2: Try file path (fallback for local development)
    firebase_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH')
    if firebase_path and os.path.exists(firebase_path):
        try:
            print(f"✅ Using Firebase config from file: {firebase_path}")
            return credentials.Certificate(firebase_path)
        except Exception as e:
            print(f"❌ Error loading Firebase config from file: {e}")

    # Option 3: Try default config file location
    default_path = 'config/salamanders-122ec-firebase-adminsdk-fbsvc-8c226bb171.json'
    if os.path.exists(default_path):
        try:
            print(f"✅ Using Firebase config from default location: {default_path}")
            return credentials.Certificate(default_path)
        except Exception as e:
            print(f"❌ Error loading Firebase config from default location: {e}")

    print("❌ Firebase credentials not found in any location")
    return None


def get_firebase_client_config():
    """Get Pyrebase client config for frontend auth"""
    return {
        "apiKey": os.getenv('FIREBASE_API_KEY'),
        "authDomain": os.getenv('FIREBASE_AUTH_DOMAIN'),
        "projectId": os.getenv('FIREBASE_PROJECT_ID'),
        "storageBucket": os.getenv('FIREBASE_STORAGE_BUCKET'),
        "messagingSenderId": os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
        "appId": os.getenv('FIREBASE_APP_ID'),
        "databaseURL": os.getenv('DATABASE_URL', '')
    }


# Initialize Firebase Admin SDK
print("🔥 Initializing Firebase Admin SDK...")
cred = get_firebase_credentials()

if cred:
    try:
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
            print("✅ Firebase Admin SDK initialized successfully")
        else:
            print("✅ Firebase Admin SDK already initialized")
    except Exception as e:
        print(f"❌ Failed to initialize Firebase Admin SDK: {e}")
else:
    print("❌ Firebase Admin SDK not initialized - missing credentials")

# Initialize Pyrebase for client-side auth
try:
    firebase_client_config = get_firebase_client_config()
    if all(firebase_client_config.values()):
        firebase = pyrebase.initialize_app(firebase_client_config)
        auth_client = firebase.auth()
        print("✅ Pyrebase client initialized successfully")
    else:
        firebase = None
        auth_client = None
        print("❌ Pyrebase client not initialized - missing config")
except Exception as e:
    firebase = None
    auth_client = None
    print(f"❌ Failed to initialize Pyrebase client: {e}")


def verify_id_token(id_token):
    """Verify Firebase ID token."""
    if not firebase_admin._apps:
        print("❌ Firebase Admin SDK not initialized")
        return None

    try:
        decoded_token = auth.verify_id_token(id_token)
        print("✅ Token verification successful")
        return decoded_token
    except Exception as e:
        print(f"❌ Token verification failed: {e}")
        return None


def google_sign_in(id_token):
    """Handle Google sign-in and return user info."""
    decoded_token = verify_id_token(id_token)
    if decoded_token:
        uid = decoded_token['uid']
        email = decoded_token.get('email', "user@example.com")
        name = decoded_token.get('name', "Unknown User")
        profile = decoded_token.get('picture', 'static/default.png')

        return {
            "uid": uid,
            "email": email,
            "name": name,
            "profile": profile
        }
    return None


class AuthService:
    def __init__(self):
        if not firebase_admin._apps:
            cred = get_firebase_credentials()
            if cred:
                try:
                    firebase_admin.initialize_app(cred)
                    print("✅ AuthService: Firebase Admin SDK initialized")
                except Exception as e:
                    print(f"❌ AuthService: Failed to initialize Firebase: {e}")

    def verify_google_token(self, id_token: str) -> dict:
        """Verify Firebase Google ID token and return user info."""
        if not firebase_admin._apps:
            raise ValueError("Firebase Admin SDK not initialized")

        try:
            decoded_token = auth.verify_id_token(id_token)
            return {
                'uid': decoded_token['uid'],
                'name': decoded_token.get('name', 'Unknown User'),
                'email': decoded_token.get('email', 'unknown@example.com'),
                'picture': decoded_token.get('picture', '')
            }
        except Exception as e:
            raise ValueError(f"Token verification failed: {str(e)}")