from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from validators import validate_password, validate_email
from flask_session import Session

app = Flask('WaterIntakeTracker')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    
    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
@app.route('/register', methods=['POST'])
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
    user = User(name=data['name'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not 'email' in data:
        return jsonify({'error': 'email is required'}), 400
    if not 'password' in data:
        return jsonify({'error': 'password is required'}), 400
    user = User.query.filter_by(email=data['email']).first()
    if user is None or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 400
    session['user_id'] = user.id
    return jsonify({'message': 'Login successful'}), 200
    
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/me', methods=['GET'])
def me():
    if not 'user_id' in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = db.session.get(User, session['user_id'])
    return jsonify({'name': user.name, 'email': user.email}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
