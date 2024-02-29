from flask import Flask, request, jsonify, render_template
import hashlib
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from flask_sqlalchemy import SQLAlchemy
import secrets
import uuid
import base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:mon_mot_de_passe@localhost/password_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

SERVER2_URL = "http://localhost:5001/encrypt"

class User(db.Model):
    __tablename__ = 'utilisateur'
    id = db.Column(db.String, primary_key=True)
    username = db.Column(db.String)
    hashed_password = db.Column(db.String)

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Login')

@app.route('/')
def home():
    return 'Welcome to the home page!'

@app.route('/create', methods=['POST', 'GET'])
def create():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        response = requests.post(SERVER2_URL, json={'password': password})
        if response.status_code == 200:

            encrypted_hash = response.json().get('encryptedHash')
            user = User(id=str(uuid.uuid4()), username=username, hashed_password=encrypted_hash)
            db.session.add(user)
            db.session.commit()

            return jsonify({'message': 'Success'}), 200
        else:
            # En cas d'échec de la requête au Serveur 2
            return jsonify({'error': 'Failed to encrypt password'}), 500

    return render_template('create.html', form=form)


SERVER2_LOGIN_URL = "http://localhost:5001/login"
@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Récupérer les données du formulaire
        username = form.username.data
        password = form.password.data
        all_users = User.query.all()
        user_to_find = str(username)
        position = next((i for i, user in enumerate(all_users) if user.username == user_to_find), None)
        user = User.query.filter_by(username=username).first()
        if user:
            response = requests.post(SERVER2_LOGIN_URL, json={'username': username, 'password': password, 'position': position})
            data_from_server2 = response.json()
            final_pass_from_server2 = data_from_server2.get('final_pass')
            username_from_server2 = data_from_server2.get('username')

            if user.hashed_password == final_pass_from_server2:
                return jsonify({'message' :'Success'}), 200
            else:
                print(final_pass_from_server2)
                return jsonify({'error': 'Login failed: Invalid credentials'}), 401
        else:
            return jsonify({'error': 'Login failed: User not found'}), 404

    return render_template('login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
