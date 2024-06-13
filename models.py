from extensions import db
from flask_login import UserMixin
import pyotp

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    tfa_secret = db.Column(db.String(32), nullable=False)
    foods = db.relationship('Food', backref='author', lazy=True)

    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.tfa_secret).provisioning_uri(self.username, issuer_name="CalorieCounter")

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    calories = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

