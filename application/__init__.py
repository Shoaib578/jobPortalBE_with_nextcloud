from flask import Flask
from config import DATABASE_URI,SECRET_KEY
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO, send,emit
import os
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY 

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI 
jwt = JWTManager(app)
db = SQLAlchemy(app)
ma= Marshmallow(app)
Migrate(app,db)
CORS(app)
from application.models import Message,User

socketIo = SocketIO(app, cors_allowed_origins="*")


@socketIo.on('connect')
def handle_connect():
    print("User just connected")

@socketIo.on('message')
def handle_message(data):
    print("Sent Message")
    sender_id, receiver_id, message = data['sender_id'], data['receiver_id'], data['message']
    if receiver_id == 'admin':
        receiver_id = User.query.filter_by(is_admin=True).first().id
    
    # Save the message to the database
    new_message = Message(sender_id=sender_id, receiver_id=receiver_id, message=message)
    db.session.add(new_message)
    db.session.commit()

    # Broadcast the message to all connected clients
    emit('message', {'sender_id': sender_id, 'receiver_id': receiver_id}, broadcast=True)


from application.routes.apis import apis
from application.routes.admin_apis import admin_apis

app.register_blueprint(apis,url_prefix='/apis')
app.register_blueprint(admin_apis,url_prefix='/admin/apis')







