from flask import Flask, request, jsonify
import hashlib
import requests
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import uuid 
from flask import Flask, render_template, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms import StringField, PasswordField, SubmitField, validators
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

#Connexnio a Postgresql
engine = create_engine('postgresql://admin_password:admin_password@localhost/password_db')
Base = declarative_base()

#class user
class User(Base):
    __tablename__ = 'utilisateur'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String)
    hashed_password = Column(String)

Session = sessionmaker(bind=engine)
Base.metadata.create_all(bind=engine)

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Login')



SERVER2_URL = "http://localhost:5001/encrypt" 

@app.route('/login', methods=['POST','GET'])
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
            session = Session()
            user = User(username=username, hashed_password=encrypted_hash)
            session.add(user)
            session.commit()
            session.close()

            return jsonify({'message': 'Success'}), 200
        else:
            # En cas d'échec de la requête au Serveur 2
            return jsonify({'error': 'Failed to encrypt password'}), 500

    return render_template('login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
