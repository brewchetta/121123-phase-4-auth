#!/usr/bin/env python3


from flask import Flask, jsonify, request, session
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt

from models import db, User, Note

app = Flask(__name__)
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

bcrypt = Bcrypt(app)

migrate = Migrate(app, db)

db.init_app(app)

CORS(app)

URL_PREFIX = '/api'

# CHECK SESSION #

@app.get(URL_PREFIX + '/check_session')
def check_session():
    user_id = session.get('user_id')
    user = User.query.where(User.id == user_id).first()
    if user:
        return user.to_dict(), 200
    else: 
        return {}, 400

# USER SIGNUP #

@app.post(URL_PREFIX + '/users')
def create_user():
    try:
        data = request.json
        new_user = User(username=data['username'])
        new_user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        return new_user.to_dict(), 201
    except Exception as e:
        return { 'error': str(e) }, 422


# SESSION LOGIN/LOGOUT#

@app.post(URL_PREFIX + '/login')
def login():
    data = request.json
    username = data['username']
    password = data['password']
    user = User.query.where(User.username == username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        return user.to_dict(), 201
    else:
        return { "error": "Invalid username or password" }, 401
    
@app.delete(URL_PREFIX + '/logout')
def logout():
    session.pop('user_id')
    return {}, 204


# EXAMPLE OTHER RESOURCES #

@app.get(URL_PREFIX + '/notes')
def get_notes():
    if session.get('user_id'):
        return jsonify( [note.to_dict() for note in Note.query.all()] ), 200
    else:
        return { "error": "NO" }, 401

@app.post(URL_PREFIX + '/notes')
def create_note():
    try:
        data = request.json
        new_note = Note(**data)
        db.session.add(new_note)
        db.session.commit()
        return jsonify( new_note.to_dict() ), 201
    except Exception as e:
        return jsonify( {'error': str(e)} ), 406

# APP RUN #

if __name__ == '__main__':
    app.run(port=5555, debug=True)
