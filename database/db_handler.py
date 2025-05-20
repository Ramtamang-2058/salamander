from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    uid = db.Column(db.String(128), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    picture = db.Column(db.String(255), default='')
    is_premium = db.Column(db.Boolean, default=False)
    word_credits = db.Column(db.Integer, default=0)
    subscription_expiry = db.Column(db.DateTime, nullable=True)
    humanizer = db.relationship('Humanizer', backref='user', lazy=True)
    payments = db.relationship('Payment', backref='user', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.name}>'


class Humanizer(db.Model):
    __tablename__ = 'humanizers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(128),
        db.ForeignKey('users.uid', name='fk_humanizers_user_id'),
        nullable=False
    )
    input_text = db.Column(db.Text, nullable=False)
    humanized_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Humanizer {self.id}>'


class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(128),
        db.ForeignKey('users.uid', name='fk_payments_user_id'),
        nullable=False
    )
    pidx = db.Column(db.String(100), unique=True, nullable=False)  # Khalti payment ID
    transaction_id = db.Column(db.String(100), nullable=True)  # Khalti transaction ID
    purchase_order_id = db.Column(db.String(100), unique=True, nullable=False)
    plan = db.Column(db.String(50), nullable=False)  # e.g., 'basic', 'premium', 'pro'
    amount = db.Column(db.Integer, nullable=False)  # Amount in paisa
    status = db.Column(db.String(50),
                       nullable=False)  # e.g., 'Initiated', 'Completed', 'Pending', 'User canceled', 'Expired'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Payment {self.pidx} - {self.status}>'

def save_user(uid, name, email):
    try:
        user = db.session.get(User, uid)
        if not user:
            user = User(uid=uid, name=name, email=email)
            db.session.add(user)
        else:
            user.name = name
            user.email = email
        db.session.commit()
        return user
    except Exception as e:
        db.session.rollback()
        raise Exception(f"Failed to save user: {str(e)}")

def save_humanizer(user_uid, input_text, humanized_text, ultra_mode=False):
    try:
        humanizer = Humanizer(
            user_id=user_uid,
            input_text=input_text,
            humanized_text=humanized_text
        )
        db.session.add(humanizer)
        db.session.commit()
        return humanizer
    except Exception as e:
        db.session.rollback()
        raise Exception(f"Failed to save humanizer: {str(e)}")


def save_payment(user_id, pidx, purchase_order_id, plan, amount, status='Initiated'):
    try:
        payment = Payment(
            user_id=user_id,
            pidx=pidx,
            purchase_order_id=purchase_order_id,
            plan=plan,
            amount=amount,
            status=status
        )
        db.session.add(payment)
        db.session.commit()
        return payment
    except Exception as e:
        db.session.rollback()
        raise Exception(f"Failed to save payment: {str(e)}")


def update_payment(pidx, status, transaction_id=None):
    try:
        payment = Payment.query.filter_by(pidx=pidx).first()
        if not payment:
            raise Exception("Payment not found")
        payment.status = status
        payment.transaction_id = transaction_id
        payment.updated_at = datetime.utcnow()
        db.session.commit()
        return payment
    except Exception as e:
        db.session.rollback()
        raise Exception(f"Failed to update payment: {str(e)}")
