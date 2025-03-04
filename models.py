from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import enum
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    openai_api_key = db.Column(db.String(256), nullable=True)
    ftp_host = db.Column(db.String(256), nullable=True)  # Add this line
    ftp_user = db.Column(db.String(256), nullable=True)  # Add this line
    ftp_pass = db.Column(db.String(256), nullable=True)  # Add this line
    role = db.Column(db.String(20), default="Regular")
    signup_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    must_reset_password = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)

class OrderStatus(enum.Enum):
    PENDING = 'Pending'
    SHIPPED = 'Shipped'
    DELIVERED = 'Delivered'
    CANCELLED = 'Cancelled'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.Enum(OrderStatus), default=OrderStatus.PENDING, nullable=False)
    user = db.relationship('User', backref=db.backref('orders', lazy=True))

class Setting(db.Model):
    __tablename__ = "settings"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

