# models.py
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import Column, Integer, String, JSON, Enum, ForeignKey
from sqlalchemy.orm import relationship
import enum

# ✅ IMPORT THE db FROM app.py
from app import db  # ← this is safe now because app.py initializes it before importing models.py

class User(db.Model, UserMixin):
    id = db.Column(Integer, primary_key=True)
    email = db.Column(String(120), unique=True, nullable=False)
    password_hash = db.Column(String(255), nullable=True)
    openai_api_key = db.Column(String(256), nullable=True)
    ftp_host = db.Column(String(256), nullable=True)
    ftp_user = db.Column(String(256), nullable=True)
    ftp_pass = db.Column(String(256), nullable=True)
    role = db.Column(String(20), default="Regular")
    signup_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    must_reset_password = db.Column(db.Boolean, default=False)
    shopify_domain = db.Column(String(255), unique=True, nullable=True)
    access_token = db.Column(String(255), nullable=True)
    shopify_data = db.Column(JSON, default={})

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ShopifyCache(db.Model):
    id = db.Column(Integer, primary_key=True)
    user_email = db.Column(String, unique=True)
    product_types = db.Column(JSON)
    vendors = db.Column(JSON)
    collections = db.Column(JSON)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class Product(db.Model):
    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)


class OrderStatus(enum.Enum):
    PENDING = 'Pending'
    SHIPPED = 'Shipped'
    DELIVERED = 'Delivered'
    CANCELLED = 'Cancelled'


class Order(db.Model):
    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(Enum(OrderStatus), default=OrderStatus.PENDING, nullable=False)
    user = relationship('User', backref=db.backref('orders', lazy=True))


class Setting(db.Model):
    __tablename__ = "settings"
    id = db.Column(Integer, primary_key=True)
    key = db.Column(String(255), unique=True, nullable=False)
    value = db.Column(String(255), nullable=False)
