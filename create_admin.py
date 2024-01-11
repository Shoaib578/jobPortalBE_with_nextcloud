from application import app,db
from application.models import User
from werkzeug.security import check_password_hash, generate_password_hash

def create_admin():
    admin = User.query.filter_by(is_admin=True).first()
    if admin:
        print("Admin Already Exist")
        pass
    else:
        admin = User(name="Admin",email="theadmin21@gmail.com",password=generate_password_hash("Games587"),is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Admin Created")


app.app_context().push()
create_admin()