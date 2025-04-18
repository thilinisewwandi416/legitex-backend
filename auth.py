from flask import Blueprint, request, jsonify
from models import db, User, PasswordResetOTP
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from utils.email_utils import generate_otp, send_otp_email

auth_bp = Blueprint('auth', __name__)
SECRET_KEY = os.environ.get('SECRET_KEY', 'a022f97d61d66eacaa5217c8e8da7923b1e4626e12d0d1bac27ac0b8c1bfe28c')

@auth_bp.route('/reset-password/request', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Email not registered'}), 404

    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    reset_entry = PasswordResetOTP(email=email, otp=otp, expires_at=expires_at)
    db.session.add(reset_entry)
    db.session.commit()

    send_otp_email(email, otp)
    return jsonify({'message': 'OTP sent to your email'})


@auth_bp.route('/reset-password/verify', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    record = PasswordResetOTP.query.filter_by(email=email, otp=otp).order_by(PasswordResetOTP.expires_at.desc()).first()

    if not record:
        return jsonify({'error': 'Invalid OTP'}), 400

    if record.expires_at < datetime.utcnow():
        return jsonify({'error': 'OTP expired'}), 400

    record.verified = True
    db.session.commit()

    return jsonify({'message': 'OTP verified. You can now reset your password'})


@auth_bp.route('/reset-password/update', methods=['POST'])
def update_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')

    record = PasswordResetOTP.query.filter_by(email=email, verified=True).order_by(PasswordResetOTP.expires_at.desc()).first()

    if not record or record.expires_at < datetime.utcnow():
        return jsonify({'error': 'OTP verification required or expired'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.set_password(new_password)
    db.session.commit()

    db.session.delete(record)
    db.session.commit()

    return jsonify({'message': 'Password updated successfully'})


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400

    user = User(email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY, algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid email or password'}), 401

def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            token = auth_header.split(" ")[1]
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except Exception as e:
            return jsonify({'error': 'Invalid token or token parsing failed', 'message': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated