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
    humanizer = db.relationship('Humanizer', backref='user', lazy=True)


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


def save_humanizer(user_uid, input_text, humanized_text, ultra_mode=False):
    try:
        humanizer = Humanizer(
            user_id=user_uid,
            input_text=input_text,
            humanized_text=humanized_text,
            # ultra_mode=ultra_mode
        )
        db.session.add(humanizer)
        db.session.commit()
        return humanizer
    except Exception as e:
        db.session.rollback()
        raise Exception(f"Failed to save humanizer: {str(e)}")
