from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import enum
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from app import db
from sqlalchemy import Column, Integer, String, JSON  # Add 'Column' and 'JSON'
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)  # ✅ Make it nullable
    openai_api_key = db.Column(db.String(256), nullable=True)
    ftp_host = db.Column(db.String(256), nullable=True)  # Add this line
    ftp_user = db.Column(db.String(256), nullable=True)  # Add this line
    ftp_pass = db.Column(db.String(256), nullable=True)  # Add this line
    role = db.Column(db.String(20), default="Regular")
    signup_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    must_reset_password = db.Column(db.Boolean, default=False)
    shopify_domain = db.Column(db.String(255), unique=True, nullable=True)
    access_token = db.Column(db.String(255), nullable=True)  # ✅ Allow NULL values
    shopify_data = Column(JSON, default={})  # Stores product types, vendors, collections


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)



class ShopifyCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String, unique=True)  # Or shop domain, whatever you're using to identify users
    product_types = db.Column(db.JSON)
    vendors = db.Column(db.JSON)
    collections = db.Column(db.JSON)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


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

