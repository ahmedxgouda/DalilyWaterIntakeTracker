from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from validators import validate_password, validate_email
from flask_session import Session
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import os
from dotenv import load_dotenv
import requests

app = Flask('WaterIntakeTracker')
load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI')


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=True)
    
    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not 'name' in data:
        return jsonify({'error': 'name is required'}), 400
    if not 'email' in data:
        return jsonify({'error': 'email is required'}), 400
    if not 'password' in data:
        return jsonify({'error': 'password is required'}), 400
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email'}), 400
    if not validate_password(data['password']):
        return jsonify({'error': 'Invalid password'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user = User(name=data['name'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not 'email' in data:
        return jsonify({'error': 'email is required'}), 400
    if not 'password' in data:
        return jsonify({'error': 'password is required'}), 400
    user = User.query.filter_by(email=data['email']).first()
    if user is None or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 400
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    session['user_id'] = user.id
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    
@app.route('/api/login/google')
def google_login():
    google_auth_url = f'https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&response_type=code&scope=openid%20email%20profile&redirect_uri={GOOGLE_REDIRECT_URI}'
    return redirect(google_auth_url)

@app.route('/api/login/google/authorized', methods=['GET'])
def google_login_authorized():
    code = request.args.get('code')
    if code is None:
        return "Error: code is required"
    token_url = 'https://oauth2.googleapis.com/token'
    token_payload = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_response = requests.post(token_url, data=token_payload, headers=token_headers)
    token_data = token_response.json()
    access_token = token_data['access_token']
    user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    user_info_headers = {'Authorization': f'Bearer {access_token}'}
    user_info_response = requests.get(user_info_url, headers=user_info_headers)
    user_info = user_info_response.json()
    user = User.query.filter_by(email=user_info['email']).first()
    if user is None:
        user = User(name=user_info['name'], email=user_info['email'])
        db.session.add(user)
        db.session.commit()
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    session['user_id'] = user.id
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/me', methods=['GET'])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    return jsonify({'name': user.name, 'email': user.email}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
