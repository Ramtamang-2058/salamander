# auth/firebase_auth.py
import firebase_admin
import pyrebase
from firebase_admin import credentials, auth

from config import FIREBASE_CONFIG, FIREBASE_SERVICE_ACCOUNT_PATH

# Firebase Admin SDK initialization
cred = credentials.Certificate(FIREBASE_SERVICE_ACCOUNT_PATH)
firebase_admin.initialize_app(cred)

# Pyrebase configuration for client-side auth
firebase = pyrebase.initialize_app(FIREBASE_CONFIG)
auth_client = firebase.auth()


def verify_id_token(id_token):
    """Verify Firebase ID token."""
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        return None


def google_sign_in(id_token):
    """Handle Google sign-in and return user info."""
    decoded_token = verify_id_token(id_token)
    if decoded_token:
        uid = decoded_token['uid']
        email = decoded_token.get('email')
        name = decoded_token.get('name')
        profile = decoded_token.get('picture')
        return {"uid": uid, "email": email, "name": name, "profile": profile}
    return None
