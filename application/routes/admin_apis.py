from flask import Blueprint, request, jsonify,current_app,abort
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime,time
from application.models import *
from application.utils import *
import jwt
admin_apis = Blueprint('admin_apis', __name__)


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




@admin_apis.route('/decode_user',methods=['GET'])
@jwt_required
def decode_user_api():
    authorization = request.headers["authorization"]
    return jsonify({
        "user":decode_user(authorization)
    })





@admin_apis.route('/save_logo',methods=['POST'])
@jwt_required
def saveLogo():

    if not request.files:
            return jsonify({"error": "No logo provided"}), 400

    logo = request.files['logo']
    save_logo(logo,'logo')
    return jsonify({"message": "Logo saved successfully", "filename": 'logo.png'}),200
    

@admin_apis.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()

   
    email = data['email']
    password = data['password']

    admin = User.query.filter_by(name="Admin",email=email,is_admin=True).first()

    if admin and check_password_hash(admin.password, password):
        access_token = encode_user(admin)


        return jsonify({
            "message": "Admin logged in successfully",
            "token": access_token
        }), 200
    else:
        return jsonify({"message": "Invalid admin credentials"}), 401


# Appointments APis Start
@admin_apis.route('/appointments', methods=['POST'])
@jwt_required
def add_appointment():
    
    data = request.get_json()
    
    if not data or not data.get('appointment_date') or not data.get('appointment_time') or not data.get('appointment_name'):
        return jsonify({"message": "Invalid request"}), 400

    appointment_date = data['appointment_date']
    appointment_time = data['appointment_time']
    appointment_name = data['appointment_name']

    user_id = data['user_id']
    date_format = "%Y-%m-%d"
    time_format = "%H:%M"


    appointment = Appointment(
        appointment_date=datetime.strptime(appointment_date, date_format),
        appointment_time=datetime.strptime(appointment_time, time_format).time(),
        appointment_name=appointment_name,
        user_id=user_id
    )

    db.session.add(appointment)
    db.session.commit()

    return jsonify({"message": "Appointment added successfully"}), 201

@admin_apis.route('/appointments/<int:appointment_id>/<int:user_id>', methods=['DELETE'])
@jwt_required
def delete_appointment(appointment_id,user_id):
    

    appointment = Appointment.query.filter_by(appointment_id=appointment_id, user_id=user_id).first()

    if not appointment:
        return jsonify({"message": "Appointment not found"}), 404

    db.session.delete(appointment)
    db.session.commit()

    return jsonify({"message": "Appointment deleted successfully"}), 200

@admin_apis.route('/appointments/user/<int:user_id>', methods=['GET'])
@jwt_required
def get_user_appointments(user_id):
    

    appointments = Appointment.query.filter_by(user_id=user_id).all()
    appointments_schema = AppointmentSchema(many=True)
    appointments_data = appointments_schema.dump(appointments)

    return jsonify({"appointments": appointments_data}), 200

# Appointments Apis End



# Expected Appointments APis Start
@admin_apis.route('/expected_appointments', methods=['POST'])
@jwt_required
def add_expected_appointment():
    
    data = request.get_json()
    
    if not data or not data.get('appointment_date') or not data.get('appointment_time') or not data.get('appointment_name'):
        return jsonify({"message": "Invalid request"}), 400

    appointment_date = data['appointment_date']
    appointment_time = data['appointment_time']
    appointment_name = data['appointment_name']

    user_id = data['user_id']
    date_format = "%Y-%m-%d"
    time_format = "%H:%M"


    appointment = ExpectedAppointment(
        ex_appointment_date=datetime.strptime(appointment_date, date_format),
        ex_appointment_time=datetime.strptime(appointment_time, time_format).time(),
        ex_appointment_name=appointment_name,
        user_id=user_id
    )

    db.session.add(appointment)
    db.session.commit()

    return jsonify({"message": "Appointment added successfully"}), 201

@admin_apis.route('/expected_appointments/<int:appointment_id>/<int:user_id>', methods=['DELETE'])
@jwt_required
def delete_expected_appointment(appointment_id,user_id):
    

    appointment = ExpectedAppointment.query.filter_by(ex_appointment_id=appointment_id, user_id=user_id).first()

    if not appointment:
        return jsonify({"message": "Appointment not found"}), 404

    db.session.delete(appointment)
    db.session.commit()

    return jsonify({"message": "Appointment deleted successfully"}), 200

@admin_apis.route('/expected_appointments/user/<int:user_id>', methods=['GET'])
@jwt_required
def get_user_expected_appointments(user_id):
    

    appointments = ExpectedAppointment.query.filter_by(user_id=user_id).all()
    appointments_schema = ExpectedAppointmentSchema(many=True)
    appointments_data = appointments_schema.dump(appointments)

    return jsonify({"appointments": appointments_data}), 200

# Expected Appointments Apis End

# Todos APis Start
@admin_apis.route('/todos', methods=['POST'])
@jwt_required

def add_todo():
    token = request.headers["authorization"]
    
    data = request.get_json()
    

    if not data or not data.get('title'):
        return jsonify({"message": "Invalid request"}), 400

    title = data['title']

    todo = Todo(title=title, user_id=data['userId'])
    db.session.add(todo)
    db.session.commit()

    return jsonify({"message": "Todo added successfully"}), 201

@admin_apis.route('/todos/<int:todo_id>/<int:userId>', methods=['DELETE'])
@jwt_required

def delete_todo(todo_id,userId):
    
    token = request.headers["authorization"]
   
    todo = Todo.query.filter_by(todo_id=todo_id, user_id=userId).first()

    if not todo:
        return jsonify({"message": "Todo not found"}), 404

    db.session.delete(todo)
    db.session.commit()

    return jsonify({"message": "Todo deleted successfully"}), 200




@admin_apis.route('/todos', methods=['GET'])
@jwt_required

def get_user_todos():
    user_id = request.args.get('user_id')
    
    todos = Todo.query.filter_by(user_id=user_id).all()
    todos_schema = TodoSchema(many=True)
    todos_data = todos_schema.dump(todos)

    return jsonify({"todos": todos_data}), 200

# Todos APis End

# Users APis Start
@admin_apis.route('/users', methods=['GET'])
@jwt_required
def get_all_users():
   
    users = User.query.filter_by(is_admin=0).all()
    user_schema = UserSchema(many=True)
    users_data = user_schema.dump(users)
    
    return jsonify({"users": users_data})


@admin_apis.route('/users', methods=['POST'])
@jwt_required

def add_user():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('name') or not data.get('password'):
        return jsonify({"message": "Invalid request"}), 400

    email = data['email']
    name = data['name']
    password = generate_password_hash(data['password'], method='sha256')

    user = User(email=email, name=name, password=password)
    db.session.add(user)
    db.session.commit()
    create_user = make_dir(user.name)
    return jsonify({"message": "User added successfully"}), 201

@admin_apis.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required
def delete_user(user_id):
    
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User deleted successfully"}), 200

# Users Apis End

# Messages APis Start


@admin_apis.route('/messages/<int:receiver_id>', methods=['GET'])
@jwt_required
def get_messages(receiver_id):
    user = decode_user(request.headers.get('authorization'))
    all_messages = Message.query.all()
    
    messages = Message.query.filter(
        ((Message.sender_id == user['id']) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == user['id']))
    ).all()

    messages_schema = MessageSchema(many=True)
    messages_data = messages_schema.dump(messages)

    return jsonify({"messages": messages_data}), 200

# Messages Apis End

# Documents APis Start
@admin_apis.route('/documents/<int:user_id>', methods=['GET'])
@jwt_required
def get_documents(user_id):
    user = decode_user(request.headers.get('authorization'))
   
    documents = Document.query.filter_by(user_id=user_id).all()
    documents_schema = DocumentSchema(many=True)
    documents_data = documents_schema.dump(documents)

    return jsonify({"documents": documents_data}), 200


@admin_apis.route('/document/<int:id>', methods=['DELETE'])
@jwt_required
def delete_document(id):
   
    document = Document.query.filter_by(document_id=id).first()

    if not document:
        return jsonify({"message": "Document not found"}), 404
    # delete_file(document.document_url) for deleting document file from nextcloud
    db.session.delete(document)
    db.session.commit()

    return jsonify({"message": "Document deleted successfully"}), 200
   

    


@admin_apis.route('/documents/<int:user_id>', methods=['POST'])
@jwt_required
def add_document(user_id):
    
    data = request.get_json()

    if not data or not data.get('document_name'):
        return jsonify({"message": "Invalid request"}), 400

    
    document_name = data['document_name']

    document = Document(
        document_name=document_name,
        user_id=user_id
    )

    db.session.add(document)
    db.session.commit()

    return jsonify({"message": "Document added successfully"}), 201

# Documents Apis End

