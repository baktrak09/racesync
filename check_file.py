from app import app, db
from models import User

with app.app_context():
    user = User.query.filter_by(email="sales@curvedracing.com").first()

    if user:
        print(f"User ID: {user.id}")
        print(f"Email: {user.email}")
        print(f"OpenAI API Key: {repr(user.openai_api_key)}")
        print(f"FTP Host: {repr(user.ftp_host)}")
        print(f"FTP User: {repr(user.ftp_user)}")
        print(f"FTP Pass: {repr(user.ftp_pass)}")
    else:
        print("User not found!")
