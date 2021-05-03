import os
import tempfile

import pytest
from flask import json

import server

user1 = {'username': 'hi',
         'email': 'test@gmail.com',
         'password': 'hej123'}
user2 = {'username': 'tjena',
         'email': 'testmaster@gmail.com',
         'password': '123hej'}

logon_user1 = {'username': 'hi',
               'password': 'hej123'}
logon_user2 = {'username': 'tjena',
               'password': '123hej'}

message = {'message': 'hello team!'}
message2 = {'message': 'hello team two!'}
message3 = {'message': 'hello team three!'}


@pytest.fixture
def client():
    db_fd, server.app.config['DATABASE'] = tempfile.mkstemp()
    server.app.config['TESTING'] = True
    client = server.app.test_client()

    with server.app.app_context():
        server.init_db()

    yield client

    os.close(db_fd)
    os.unlink(server.app.config['DATABASE'])


def test_empty_db(client):
    """Start with a blank database"""

    rv = client.get('/')
    assert b'Index Page' in rv.data


def test_add_user(client):
    """Add a user"""

    rv = client.post('/user', json=user1)
    assert b'User hi added' in rv.data


def test_logout_user(client):
    """Logout a user"""

    client.post('/user', json=user1)
    rv = client.post('/user/login', json=logon_user1)
    access_token = rv.data
    JWT = json.loads(access_token)['access_token']
    rv = client.post('/user/logout', headers={'Authorization': "Bearer " + JWT})
    assert b'JWT Revoked' in rv.data


def test_save_and_mark_message(client):
    """Save a message and mark as read by user"""

    client.post('/user', json=user1)
    rv = client.post('/user/login', json=logon_user1)
    access_token = rv.data
    JWT = json.loads(access_token)['access_token']

    rv = client.post('/messages', json=message, headers={'Authorization': "Bearer " + JWT})
    assert b'{"id":1}' in rv.data

    rv = client.post('/messages/1/read/1', headers={'Authorization': "Bearer " + JWT})
    assert b'Marked as read' in rv.data


def test_a_lot(client):
    """Testing a lot of functionality in the code
    based on return comments from lab assistant"""


    client.post('/user', json=user1)
    rv = client.post('/user/login', json=logon_user1)
    access_token = rv.data
    JWT = json.loads(access_token)['access_token']

    rv = client.post('/messages', json=message, headers={'Authorization': "Bearer " + JWT})
    assert b'{"id":1}' in rv.data
    rv = client.post('/messages', json=message2, headers={'Authorization': "Bearer " + JWT})
    assert b'{"id":2}' in rv.data
    rv = client.post('/messages', json=message3, headers={'Authorization': "Bearer " + JWT})
    assert b'{"id":3}' in rv.data

    #Get all messages
    rv = client.get('/messages')
    print(rv.data)

    #Get 1 message
    rv = client.get('/messages/2')
    print(rv.data)

    #Delete 1 message
    rv = client.delete('/messages/2', headers={'Authorization': "Bearer " + JWT})
    print(rv.data)

    #Get all messages again
    rv = client.get('/messages')
    print(rv.data)

    #Mark message as read
    rv = client.post('/messages/3/read/1', headers={'Authorization': "Bearer " + JWT})
    print(rv.data)

    #Try mark same message again
    rv = client.post('/messages/3/read/1', headers={'Authorization': "Bearer " + JWT})
    print(rv.data)

    #Get all messages again
    rv = client.get('/messages')
    print(rv.data)

    client.post('/messages', json=message3, headers={'Authorization': "Bearer " + JWT})

    #Get all unread messages by a user
    rv = client.get('/messages/unread/1', headers={'Authorization': "Bearer " + JWT})
    print(rv.data)

    #Try adding same user again
    rv = client.post('/user', json=user1)
    print(rv.data)

    #Add new user
    rv = client.post('/user', json=user2)
    print(rv.data)

    client.post('/messages', json=message2, headers={'Authorization': "Bearer " + JWT})
    client.post('/messages', json=message, headers={'Authorization': "Bearer " + JWT})

    #Mark message as read by user 1
    rv = client.post('/messages/5/read/1', headers={'Authorization': "Bearer " + JWT})
    print(rv.data)

    #Mark message as read by user 2
    rv = client.post('/messages/5/read/2', headers={'Authorization': "Bearer " + JWT})
    print(rv.data)

    #Get all messages again
    rv = client.get('/messages')
    print(rv.data)

    rv = client.post('/messages/1/read/1', headers={'Authorization': "Bearer " + JWT})
    assert b'Marked as read' in rv.data

