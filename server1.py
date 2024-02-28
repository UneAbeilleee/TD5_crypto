from flask import Flask, request, jsonify, render_template
import hashlib
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from flask_sqlalchemy import SQLAlchemy
import secrets
import uuid

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

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Récupérer les données du formulaire
        username = form.username.data
        password = form.password.data

        # Hasher le mot de passe
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Envoyer le mot de passe haché au Serveur 2 pour le chiffrement
        response = requests.post(SERVER2_URL, json={'hashedPassword': hashed_password})

        if response.status_code == 200:
            # Si la requête réussit, récupérez le hash chiffré du Serveur 2
            encrypted_hash = response.json().get('encryptedHash')

            # Insérer le nom d'utilisateur et le hash encrypté dans la base de données
            user = User(id=str(uuid.uuid4()), username=username, hashed_password=encrypted_hash)
            db.session.add(user)
            db.session.commit()

            return jsonify({'message': 'Success'}), 200
        else:
            # En cas d'échec de la requête au Serveur 2
            return jsonify({'error': 'Failed to encrypt password'}), 500

    return render_template('login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
