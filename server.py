from datetime import timedelta, datetime, timezone

from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required, get_jwt
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

import os

if 'NAMESPACE' in os.environ and os.environ['NAMESPACE'] == 'heroku':
    db_uri = os.environ['DATABASE_URL']
    debug_flag = False
else:  # when running localy: use sqlite
    db_path = os.path.join(os.path.dirname(__file__), 'app.db')
    db_uri = 'sqlite:///{}'.format(db_path)
    debug_flag = True

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['JWT_SECRET_KEY'] = "test_key"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

readBy_relation = db.Table('readBy_relation',
                           db.Column('message_id', db.Integer, db.ForeignKey('messages.id'), primary_key=True),
                           db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
                           )


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    passw_hash = db.Column(db.LargeBinary())

    def __repr__(self):
        return self.username


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(140), unique=False, nullable=False)
    readBy = db.relationship('User', secondary=readBy_relation, lazy='subquery',
                             backref=db.backref('messages', lazy=True))


class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)


def init_db():
    db.drop_all()
    db.create_all()


@app.route("/refresh", methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None


@app.route('/')
def index():
    return 'Index Page'


@app.route('/hello')
def hello_world():
    return 'Hello World!'


@app.route('/messages', methods=['POST', 'GET'])
@jwt_required(optional=True)
def messages():
    """Post a new message or get all messages"""

    current_identity = get_jwt_identity()
    if request.method == 'POST' and current_identity:
        msg_data = request.json
        if len(msg_data['message']) > 140:
            return "Message to long", 400
        new_msg = Messages(message=msg_data['message'])
        db.session.add(new_msg)
        db.session.commit()
        ret_id = {'id': new_msg.id}
        return jsonify(ret_id)
    elif request.method == 'POST' and not current_identity:
        return "You need to be logged in to post messages", 401

    if request.method == 'GET':
        all_messages = Messages.query.all()
        return_list = []
        for current_message in all_messages:
            readby_list = []
            for current in current_message.readBy:
                readby_list.append(current.id)
            return_list.append({'id': current_message.id,
                                'message': current_message.message,
                                'readBy': readby_list})
        return jsonify(return_list)


@app.route('/messages/<MessageID>', methods=['GET', 'DELETE'])
@jwt_required(optional=True)
def message(MessageID):
    """Get or delete specific message"""

    current_identity = get_jwt_identity()
    check_id = Messages.query.filter(Messages.id == MessageID).first()

    if check_id is None:
        return "There is no message with that ID", 400

    if request.method == 'GET':
        get_message = Messages.query.get(MessageID)
        return_message = {'id': get_message.id,
                          'message': get_message.message,
                          'readBy': get_message.readBy}
        return return_message

    if request.method == 'DELETE' and current_identity:
        Messages.query.filter(Messages.id == MessageID).delete()
        db.session.commit()
        return "Message deleted", 200
    elif request.method == 'DELETE' and not current_identity:
        return "You need to be logged in to delete messages", 401


@app.route('/messages/<MessageID>/read/<UserId>', methods=['POST'])
@jwt_required()
def mark_as_read(MessageID, UserId):
    """Mark specific message as read by specific user"""

    check_message_id = Messages.query.filter(Messages.id == MessageID).first()
    check_user_id = User.query.filter(User.id == UserId).first()

    if check_message_id is None:
        return "There is no message with that ID", 400
    elif check_user_id is None:
        return "There is no user with that ID", 400

    msg = Messages.query.filter(Messages.id == MessageID).first()
    user = User.query.filter(User.id == UserId).first()

    for current_user in msg.readBy:
        if current_user == user:
            return "User has already read this post", 500

    msg.readBy.append(user)
    db.session.commit()
    return "Marked as read", 200


@app.route('/messages/unread/<UserId>', methods=['GET'])
@jwt_required()
def get_unread(UserId):
    """Get all messages that are unread by specific user"""

    user = User.query.filter(User.id == UserId).first()
    unread_messages = Messages.query.filter(~Messages.readBy.contains(user)).all()

    unread_list = []
    for current_message in unread_messages:
        readby_list = []
        for current in current_message.readBy:
            readby_list.append(current.id)
        unread_list.append({'id': current_message.id,
                            'message': current_message.message,
                            'readBy': readby_list})

    return jsonify(unread_list)


@app.route('/user', methods=['POST'])
def create_user():
    """Create a new user and add to database"""

    user_data = request.json

    uname_check = User.query.filter(User.username == user_data['username']).first()
    uemail_check = User.query.filter(User.email == user_data['email']).first()

    if uname_check is None and uemail_check is None:
        user = User(username=user_data['username'],
                    email=user_data['email'],
                    passw_hash=bcrypt.generate_password_hash(user_data['password']))
        db.session.add(user)
        db.session.commit()
        return "User " + repr(user) + " added", 200
    else:
        return "User or email already exists", 500


@app.route('/user/login', methods=['POST'])
def login_user():
    """Login function"""

    login_credentials = request.json
    uname = login_credentials['username']
    upass = login_credentials['password']
    check_user = User.query.filter(User.username == uname).first()
    if check_user is None:
        return "User or password not matching"
    else:
        check_pass = bcrypt.check_password_hash(check_user.passw_hash, upass)
        if check_pass:
            access_token = create_access_token(identity=uname)
            return jsonify(access_token=access_token)
        else:
            return "User or password not matching"


@app.route('/user/logout', methods=['POST'])
@jwt_required()
def logout_user():
    """Logout function"""

    jti = get_jwt()['jti']
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return "JWT Revoked", 200


if __name__ == '__main__':
    app.run()
