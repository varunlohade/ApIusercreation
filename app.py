from flask import Flask, json, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
from werkzeug.serving import WSGIRequestHandler
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_mail import Mail,Message
from random import randint

app = Flask(__name__)
mail=Mail(app)

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"]=465
app.config["MAIL_USERNAME"]='enter email here'
app.config['MAIL_PASSWORD']="enter password here"
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
mail=Mail(app)
otp=randint(1000,9999)

app.config['SECRET_KEY']='thisissecret'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///scholarship.db'
db= SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email=db.Column(db.String(90))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    otp=randint(1000,9999)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.confid['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user,*args,**kwargs)
    return decorated
@app.route('/user',methods=['GET'])
def get_all_users():
    # if not current_user.admin:
    #     return jsonify({'message':'User cannot perform this action'})
    users = User.query.all()
    output = []
    for user in users:
        user_data= {}
        user_data['public_id']=user.public_id
        user_data['name']=user.name
        user_data['email']=user.email
        user_data['password']=user.password
        user_data['admin']=user.admin
        output.append(user_data)
    return jsonify({'users': output})

@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found"})
    user_data= {}
    user_data['public_id']=user.public_id
    user_data['name']=user.name
    user_data['email']=user.email
    user_data['password']=user.password
    user_data['admin']=user.admin



    return jsonify({"user":user_data})
@app.route('/verify', methods=['POST'])

def create_user():

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),email=data['email'], name=data['name'], password=hashed_password, admin=False)
    msg=Message(subject='OTP',sender='learnmailbyvarun@gmail.com',recipients=[data['email']])
    msg.body=str(otp)
   
    print("This is the msg that will be send ",msg)
    print("This is the otp ",otp)
    print("This is the info of new_user not verified",data['email'])
    mail.send(msg) 
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'OTP-200'})
    
    # return jsonify({'message':'New User Created!'})
@app.route('/validate', methods=['POST'])
def validate():
    user_otp=request.get_json()
    print(otp)
    print("this is inside validate ",user_otp['user_otp'])
    if otp==int(user_otp['user_otp']):
        return jsonify({"message":"New User created"})
        # db.session.add(create_user.new_user)
        # db.session.commit()
    return jsonify({'message': 'Error: Incorrect OTP'})

@app.route('/user/<public_id>',methods=['PUT'])
@token_required

def promote_user(current_user,public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found"})

    user.admin=True
    db.session.commit()
    return jsonify({"message": "The User has been promoted"})

@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message":"User has been deleted"})

@app.route('/login',methods=['POST'])

def login():
    # auth = request.authorization
    auth = request.get_json()
    print("Welcome to login page")
    if not auth or not auth['username'] or not auth['password']:
        return make_response('incorrect credentials', {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth['username']).first()

    if not user:
        return make_response('user not found', {'WWW-Authenticate' : 'Basic realm="Login required!"','msg':'user not found',})

    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'],algorithm="HS256")
        print("This is public id",user.public_id)
        return jsonify({'token' : jwt.decode(token,'thisissecret',algorithms="HS256"),'msg':'loginsuccess'})

    return jsonify({'msg': 'Login required'})

@app.route("/")
def index():
    return "<h1>Welcome to Scholarship test api server Invofinity</h1>"

if __name__ =="__main__":
    WSGIRequestHandler.protocol_version ="HTTP/1.1"
    app.run(host='127.0.0.1',port=5000)

