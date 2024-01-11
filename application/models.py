from application import db,ma,app
from werkzeug.security import check_password_hash, generate_password_hash




# Users Table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    appointments = db.relationship('Appointment', backref='user', lazy=True, cascade='all, delete-orphan')
    todos = db.relationship('Todo', backref='user', lazy=True, cascade='all, delete-orphan')
    document = db.relationship('Document', backref='user', lazy=True, cascade='all, delete-orphan')
   
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'name', 'password', 'is_admin')



# Appointments Table
class Appointment(db.Model):
    appointment_id = db.Column(db.Integer, primary_key=True)
    appointment_name = db.Column(db.String(200), nullable=False)

    appointment_date = db.Column(db.Date, nullable=False)
    appointment_time = db.Column(db.Time, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    
class AppointmentSchema(ma.Schema):
    class Meta:
        fields = ('appointment_id','appointment_name', 'appointment_date', 'appointment_time', 'user_id')




#Expected Appointments
class ExpectedAppointment(db.Model):
    ex_appointment_id = db.Column(db.Integer, primary_key=True)
    ex_appointment_name = db.Column(db.String(200), nullable=False)

    ex_appointment_date = db.Column(db.Date, nullable=False)
    ex_appointment_time = db.Column(db.Time, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    
class ExpectedAppointmentSchema(ma.Schema):
    class Meta:
        fields = ('ex_appointment_id','ex_appointment_name', 'ex_appointment_date', 'ex_appointment_time', 'user_id')

# Todos Table
class Todo(db.Model):
    todo_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
class TodoSchema(ma.Schema):
    class Meta:
        fields = ('todo_id', 'title', 'user_id')

# Documents Table
class Document(db.Model):
    document_id = db.Column(db.Integer, primary_key=True)
    document_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    document_url = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(255), nullable=True,default="Not Published")
class DocumentSchema(ma.Schema):
    class Meta:
        fields = ('document_id', 'document_name', 'user_id','status','document_url')

# Messages Table
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    receiver_id = db.Column(db.Integer,  nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    message = db.Column(db.String(500), nullable=False)
   
   
class MessageSchema(ma.Schema):
    class Meta:
        fields = ('id', 'sender_id', 'receiver_id', 'message','is_read')



