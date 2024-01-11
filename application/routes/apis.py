from flask import Blueprint, request, jsonify,current_app,abort
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime,time
from application.models import *
from application.utils import *
import jwt
import os
apis = Blueprint('apis', __name__)


def encode_user(payload):
    
    encoded_data = jwt.encode(payload={"id":payload.id,"name":payload.name,"email":payload.email,"is_admin":payload.is_admin},
                              key=current_app.config['SECRET_KEY'],
                              algorithm="HS256")

    return encoded_data


def decode_user(token):
    decoded_data = jwt.decode(jwt=token,
                              key=current_app.config['SECRET_KEY'],
                              algorithms=["HS256"])
    
    user = User.query.filter_by(id=decoded_data['id']).first()
    user_schema = UserSchema(many=False)
    user_data = user_schema.dump(user)
    if not user:
        return False
        
    return user_data


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "authorization" in request.headers:
            token = request.headers["authorization"]
        if not token:
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        try:
            data=jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user=User.query.filter_by(id=data["id"]).first()
            if current_user is None:
                return {
                "message": "Invalid Authentication token!",
                "data": None,
                "error": "Unauthorized"
            }, 401
            
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": None,
                "error": str(e)
            }, 401

        return f( *args, **kwargs)

    return decorated




@apis.route('/decode_user',methods=['GET'])
@jwt_required
def decode_user_api():
    authorization = request.headers["authorization"]
    return jsonify({
        "user":decode_user(authorization)
    })






# User Apis Start
@apis.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        access_token = encode_user(user)

        return jsonify({
            "message": "Logged in successfully",
            "token": access_token
        }), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401



@apis.route('/check_user')
@jwt_required
def check_user():
    token = request.headers["authorization"]
    user = decode_user(token)

    if user:
        return jsonify({
            "found":True,
            "user":user
        }),200
    else:
        return jsonify({
            "found":False,
            "user":user

        }),200



@apis.route('/check_missings_of_users')
@jwt_required
def check_missings_of_users():
    token = request.headers["authorization"]
    user = decode_user(token)
    admin = User.query.filter_by(is_admin=True).first()
    documents = Document.query.filter_by(user_id=user['id'],status='Not Published').count()
    messages = Message.query.filter(
        
        ((Message.sender_id == admin.id) & (Message.receiver_id == user['id']) & (Message.is_read == False))
    ).count()
    return jsonify({
        "user":user['name'],
        "missing_docs":documents,
        "missing_messages":messages
    })


@apis.route('/mark_all_messages_read',methods=['PUT'])
@jwt_required
def mark_all_messages_read():
    token = request.headers["authorization"]
    user = decode_user(token)
    admin = User.query.filter_by(is_admin=True).first()
    
    messages = Message.query.filter(
        
        ((Message.sender_id == admin.id) & (Message.receiver_id == user['id']) & (Message.is_read == False))
    ).all()

    for message in messages:
        message.is_read = True

    # Commit the changes to the database
    db.session.commit()


    return jsonify({
       "message":"success"
    }),200



# Todos APis Start
@apis.route('/todos', methods=['POST'])
@jwt_required

def add_todo():
    token = request.headers["authorization"]
    
    data = request.get_json()
    user = decode_user(token)

    if not data or not data.get('title'):
        return jsonify({"message": "Invalid request"}), 400

    title = data['title']

    todo = Todo(title=title, user_id=user['id'])
    db.session.add(todo)
    db.session.commit()

    return jsonify({"message": "Todo added successfully"}), 201

@apis.route('/todos/<int:todo_id>', methods=['DELETE'])
@jwt_required

def delete_todo(todo_id):
    
    token = request.headers["authorization"]
    user = decode_user(token)
    todo = Todo.query.filter_by(todo_id=todo_id, user_id=user['id']).first()

    if not todo:
        return jsonify({"message": "Todo not found"}), 404

    db.session.delete(todo)
    db.session.commit()

    return jsonify({"message": "Todo deleted successfully"}), 200

@apis.route('/todos', methods=['GET'])
@jwt_required

def get_user_todos():
    token = request.headers["authorization"]
    user = decode_user(token)
    
    todos = Todo.query.filter_by(user_id=user['id']).all()
    todos_schema = TodoSchema(many=True)
    todos_data = todos_schema.dump(todos)

    return jsonify({"todos": todos_data}), 200

# Todos APis End


# Appointments Apis Start

@apis.route('/appointments', methods=['GET'])
@jwt_required

def get_appointments():
    token = request.headers["authorization"]
    user = decode_user(token)
    
    appointments = Appointment.query.filter_by(user_id=user['id']).all()
    appointment_schema = AppointmentSchema(many=True)
    appointment_data = appointment_schema.dump(appointments)

    return jsonify({"appointments": appointment_data,"user":user['name']}), 200


#Appointments Apis End


# Appointments Apis Start

@apis.route('/expected_appointments', methods=['GET'])
@jwt_required

def get_expected_appointments():
    token = request.headers["authorization"]
    user = decode_user(token)
    
    appointments = ExpectedAppointment.query.filter_by(user_id=user['id']).all()
    appointment_schema = ExpectedAppointmentSchema(many=True)
    appointment_data = appointment_schema.dump(appointments)

    return jsonify({"appointments": appointment_data,"user":user['name']}), 200


#Appointments Apis End


#Documents Apis Start

@apis.route('/documents', methods=['GET'])
@jwt_required
def get_documents():
    token = request.headers["authorization"]
    user = decode_user(token)
    
    documents = Document.query.filter_by(user_id=user['id']).all()
    documents_schema = DocumentSchema(many=True)
    documents_data = documents_schema.dump(documents)

    return jsonify({"documents": documents_data,"user":user['name']}), 200



@apis.route('/submit_document',methods=['POST'])
@jwt_required
def submit_document():
    token = request.headers["authorization"]
    user = decode_user(token)
    document_file = request.files['document_file']
    document_id = request.form['document_id']
   
    if document_file and document_id:
        saved_file = upload_file(f'PowerdriveApp/{user["name"]}/',document_file)
        document = Document.query.filter_by(user_id=user['id'],document_id=document_id).first()
        document.document_url = get_file_link(f'PowerdriveApp/{user["name"]}/{saved_file}')
        document.status = "uploaded"
        db.session.commit()
        return jsonify({
            "message":"Success"
        }),200
    else:
        return jsonify({
            "message":"Failed to upload"
        }),400
    

#MEssages Apis Start

@apis.route('/messages', methods=['GET'])
@jwt_required
def get_messages():
    user = decode_user(request.headers.get('authorization'))
    admin = User.query.filter_by(is_admin=True).first()
    
    messages = Message.query.filter(
        ((Message.sender_id == user['id']) & (Message.receiver_id == admin.id)) |
        ((Message.sender_id == admin.id) & (Message.receiver_id == user['id']))
    ).all()

    messages_schema = MessageSchema(many=True)
    messages_data = messages_schema.dump(messages)

    return jsonify({"messages": messages_data}), 200




