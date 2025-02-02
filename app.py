from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from validators import validate_password, validate_email
from flask_session import Session
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import os
from dotenv import load_dotenv
import requests
from datetime import datetime

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
        return f'{self.id}-{self.name}-{self.email}'
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
class WaterIntake(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    intake = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(10), nullable=False, default='ml')
    
    def __repr__(self):
        return f'{self.id}-{self.user_id}-{self.date}-{self.intake}'
    
class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    goal = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(10), nullable=False, default='ml')
    date = db.Column(db.Date, nullable=False) 
    
    def __repr__(self):
        return f'{self.id}-{self.user_id}-{self.goal}'
    
@app.route('/api/water/intake', methods=['POST'])
@jwt_required()
def add_intake():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    data = request.get_json()
    if not 'intake' in data:
        return jsonify({'error': 'intake is required'}), 400
    intake = None
    if 'unit' in data and data['unit'] not in ['ml', 'l']:
        return jsonify({'error': 'Invalid unit'}), 400
    unit = data.get('unit', 'ml')
    date = datetime.now().date() if not 'date' in data else datetime.strptime(data['date'], '%Y-%m-%d')
    goal = Goal.query.filter_by(user_id=id, date=date).first()
    if not goal:
        return jsonify({'error': 'Goal not set yet'}), 400
    if goal.unit != unit:
        return jsonify({'error': 'Goal unit does not match intake unit'}), 400
    intake = WaterIntake(user_id=id, intake=data['intake'], unit=unit, date=date)
    db.session.add(intake)
    db.session.commit()
    return jsonify({'message': 'Intake added successfully'}), 201

@app.route('/api/water/intake/<int:id>', methods=['PUT'])
@jwt_required()
def update_intake(id):
    user = get_jwt_identity()
    user_id = int(user.split('-')[0])
    intake = WaterIntake.query.filter_by(id=id, user_id=user_id).first()
    if not intake:
        return jsonify({'error': 'Intake not found'}), 404
    data = request.get_json()
    if 'intake' in data:
        intake.intake = data['intake']
    db.session.commit()
    return jsonify({'message': 'Intake updated successfully'}), 200

@app.route('/api/water/intake/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_intake(id):
    user = get_jwt_identity()
    user_id = int(user.split('-')[0])
    intake = WaterIntake.query.filter_by(id=id, user_id=user_id).first()
    if not intake:
        return jsonify({'error': 'Intake not found'}), 404
    db.session.delete(intake)
    db.session.commit()
    return jsonify({'message': 'Intake deleted successfully'}), 200

@app.route('/api/water/intake', methods=['GET'])
@jwt_required()
def get_intakes():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    intakes = WaterIntake.query.filter_by(user_id=id).all()
    return jsonify(
        {
            "intakes": [{'id': intake.id,'date': intake.date, 'intake': intake.intake, 'unit': intake.unit} for intake in intakes]
        }
    ), 200

@app.route('/api/progress', methods=['GET'])
@jwt_required()
def progress():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    intakes = WaterIntake.query.filter_by(user_id=id).all()
    total_intake = sum([intake.intake for intake in intakes])
    return jsonify({'total_intake': total_intake}), 200

@app.route('/api/progress/day', methods=['GET'])
@jwt_required()
def progress_day():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    today = datetime.now().date()
    intakes = WaterIntake.query.filter(WaterIntake.user_id==id, WaterIntake.date==today).all()
    total_intake = sum([intake.intake for intake in intakes])
    goal = Goal.query.filter_by(user_id=id, date=today).first()
    if not goal:
        return jsonify({'error': 'Goal not set yet'}), 400
    return jsonify({'total_intake': total_intake, 'goal': goal.goal, 'unit': goal.unit}), 200

@app.route('/api/progress/week', methods=['GET'])
@jwt_required()
def progress_week():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    today = datetime.now().date()
    start_date = today.replace(day=today.day-7)
    intakes = WaterIntake.query.filter(WaterIntake.user_id==id, WaterIntake.date>=start_date, WaterIntake.date<=today).all()
    total_intake = sum([intake.intake for intake in intakes])
    return jsonify({'total_intake': total_intake}), 200

@app.route('/api/progress/month', methods=['GET'])
@jwt_required()
def progress_month():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    today = datetime.now().date()
    start_date = today.replace(month=today.month-1)
    intakes = WaterIntake.query.filter(WaterIntake.user_id==id, WaterIntake.date>=start_date, WaterIntake.date<=today).all()
    total_intake = sum([intake.intake for intake in intakes])
    return jsonify({'total_intake': total_intake}), 200

@app.route('/api/progress/year', methods=['GET'])
@jwt_required()
def progress_year():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    today = datetime.now().date()
    start_date = today.replace(year=today.year-1)
    intakes = WaterIntake.query.filter(WaterIntake.user_id==id, WaterIntake.date>=start_date, WaterIntake.date<=today).all()
    total_intake = sum([intake.intake for intake in intakes])
    return jsonify({'total_intake': total_intake}), 200

@app.route('/api/goal', methods=['POST'])
@jwt_required()
def set_goal():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    data = request.get_json()
    if not 'goal' in data:
        return jsonify({'error': 'goal is required'}), 400
    if 'unit' in data and data['unit'] not in ['ml', 'l']:
        return jsonify({'error': 'Invalid unit'}), 400
    if Goal.query.filter_by(user_id=id, date=datetime.now().date()).first():
        return jsonify({'error': 'Goal already set for today'}), 400
    date = datetime.now().date() if not 'date' in data else datetime.strptime(data['date'], '%Y-%m-%d')
    goal = Goal(user_id=id, goal=data['goal'], unit=data.get('unit', 'ml'), date=date)
    db.session.add(goal)
    db.session.commit()
    return jsonify({'message': 'Goal set successfully'}), 201

@app.route('/api/goal', methods=['GET'])
@jwt_required()
def get_goal():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    goal = Goal.query.filter_by(user_id=id, date=datetime.now().date()).first()
    if not goal:
        return jsonify({'error': 'Goal not set yet'}), 400
    return jsonify({'goal': goal.goal, 'unit': goal.unit}), 200

@app.route('/api/goal', methods=['PUT'])
@jwt_required()
def update_goal():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    data = request.get_json()
    if not 'goal' in data:
        return jsonify({'error': 'goal is required'}), 400
    goal = Goal.query.filter_by(user_id=id, date=datetime.now().date()).first()
    if not goal:
        return jsonify({'error': 'Goal not set yet'}), 400
    goal.goal = data['goal']
    db.session.commit()
    return jsonify({'message': 'Goal updated successfully'}), 200

@app.route('/api/goal', methods=['DELETE'])
@jwt_required()
def delete_goal():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    goal = Goal.query.filter_by(user_id=id, date=datetime.now().date()).first()
    if not goal:
        return jsonify({'error': 'Goal not set yet'}), 400
    db.session.delete(goal)
    db.session.commit()
    return jsonify({'message': 'Goal deleted successfully'}), 200

@app.route('/api/goal/reset', methods=['POST'])
@jwt_required()
def reset():
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    today = datetime.now().date()
    intakes = WaterIntake.query.filter_by(user_id=id, date=today).all()
    for intake in intakes:
        db.session.delete(intake)
    db.session.commit()
    return jsonify({'message': 'Goal reset successfully'}), 200

    
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
    access_token = create_access_token(identity=str(user))
    refresh_token = create_refresh_token(identity=str(user))
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
    user = get_jwt_identity()
    id = int(user.split('-')[0])
    user = db.session.get(User, id)
    return jsonify({'name': user.name, 'email': user.email}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
