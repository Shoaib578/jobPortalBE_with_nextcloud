from application import socketIo,db,app

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        socketIo.run(app,host='0.0.0.0', port=5000,debug=True)