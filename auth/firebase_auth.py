# auth/firebase_auth.py - Updated to work with your existing code

import os
import json
import firebase_admin
import pyrebase
from firebase_admin import credentials, auth


def get_firebase_credentials():
    """Get Firebase credentials from environment or file"""
    # Try to get credentials from environment variable (JSON string)
    firebase_config_str = os.getenv('FIREBASE_CONFIG')

    if firebase_config_str:
        try:
            # Parse JSON string from environment variable
            config_dict = json.loads(firebase_config_str)
            return credentials.Certificate(config_dict)
        except json.JSONDecodeError as e:
            print(f"Error parsing FIREBASE_CONFIG: {e}")
            return None

    # Fallback to file path for local development
    try:
        from config import FIREBASE_SERVICE_ACCOUNT_PATH
        if os.path.exists(FIREBASE_SERVICE_ACCOUNT_PATH):
            return credentials.Certificate(FIREBASE_SERVICE_ACCOUNT_PATH)
    except ImportError:
        pass

    print("Warning: Firebase credentials not found in environment or config file")
    return None


def get_firebase_client_config():
    """Get Pyrebase client config"""
    try:
        from config import FIREBASE_CONFIG
        return FIREBASE_CONFIG
    except ImportError:
        # You might need to set this as env var too if needed for pyrebase
        print("Warning: FIREBASE_CONFIG not found in config file")
        return None


# Firebase Admin SDK initialization
cred = get_firebase_credentials()
if cred:
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
else:
    print("Firebase Admin SDK not initialized - missing credentials")

# Pyrebase configuration for client-side auth
firebase_client_config = get_firebase_client_config()
if firebase_client_config:
    firebase = pyrebase.initialize_app(firebase_client_config)
    auth_client = firebase.auth()
else:
    firebase = None
    auth_client = None


def verify_id_token(id_token):
    """Verify Firebase ID token."""
    if not firebase_admin._apps:
        print("Firebase not initialized")
        return None

    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        print(f"Token verification failed: {e}")
        return None


def google_sign_in(id_token):
    """Handle Google sign-in and return user info."""
    decoded_token = verify_id_token(id_token)
    if decoded_token:
        uid = decoded_token['uid']
        email = decoded_token.get('email') or "human@gmail.com"
        name = decoded_token.get('name')
        profile = decoded_token.get('picture') or 'static/default.png'
        return {"uid": uid, "email": email, "name": name, "profile": profile}
    return None


class AuthService:
    def __init__(self):
        if not firebase_admin._apps:
            cred = get_firebase_credentials()
            if cred:
                firebase_admin.initialize_app(cred)

    def verify_google_token(self, id_token: str) -> dict:
        """Verify Firebase Google ID token and return user info."""
        if not firebase_admin._apps:
            raise ValueError("Firebase not initialized")

        try:
            decoded_token = auth.verify_id_token(id_token)
            return {
                'uid': decoded_token['uid'],
                'name': decoded_token.get('name', 'Unknown User'),
                'email': decoded_token.get('email', 'unknown@gmail.com'),
                'picture': decoded_token.get('picture', '')
            }
        except Exception as e:
            raise ValueError(f"Token verification failed: {str(e)}")