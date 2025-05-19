
from firebase_admin import  firestore


# Firestore client
db = firestore.client()

def save_user_to_firestore(uid, name, email):
    # Save user data to Firestore
    user_ref = db.collection('users').document(uid)
    user_ref.set({
        'uid': uid,
        'name': name,
        'email': email,
        'created_at': firestore.SERVER_TIMESTAMP
    })
