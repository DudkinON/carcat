#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, abort, g
from models import create_user, get_user_by_username
from models import create_item, User, get_items_by_category
from models import get_categories, get_items, get_user_by_email
from models import user_exist, update_user, remove_user, get_user_by_id
from data_control import email_is_valid
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from httplib2 import Http
from flask import make_response
from requests import get as r_get
from json import dumps, loads


auth = HTTPBasicAuth()

app = Flask(__name__)


@auth.verify_password
def verify_password(_login, password):
    # Try to see if it's a token firs   t
    user_id = User.verify_auth_token(_login)
    if user_id:
        user = get_user_by_id(user_id)
    else:
        user = get_user_by_email(_login)
        if not user:
            user = get_user_by_username(_login)
            if not user or not user.verify_password(password):
                return False
        else:
            if not user.verify_password(password):
                return False
    g.user = user
    return True


@app.route('/clientOAuth')
def start():
    return jsonify()


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    # STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = Http()
        result =loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # # Verify that the access token is used for the intended user.
        # gplus_id = credentials.id_token['sub']
        # if result['user_id'] != gplus_id:
        #     response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # # Verify that the access token is valid for this app.
        # if result['issued_to'] != CLIENT_ID:
        #     response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # stored_credentials = login_session.get('credentials')
        # stored_gplus_id = login_session.get('gplus_id')
        # if stored_credentials is not None and gplus_id == stored_gplus_id:
        #     response = make_response(json.dumps('Current user is already connected.'), 200)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        # STEP 3 - Find User or make a new one

        # Get user info
        h = Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = r_get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']
        first_name = data.get('first_name')
        last_name = data.get('last_name')

        # see if user exists, if it doesn't make a new one
        user = get_user_by_email(email=email)
        if not user:
            user = create_user(username=name, picture=picture, email=email,
                               first_name=first_name, last_name=last_name,
                               password=None)
        # STEP 4 - Make token
        token = user.generate_auth_token(600)

        # STEP 5 - Send back token to the client
        return jsonify({'token': token.decode('ascii')})

        # return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'


@app.route('/')
def home_page():
    items = get_items(limit=10)
    json = [item.serialize for item in items]
    print request.headers
    # print {item.serialize for item in items}

    return jsonify(json)


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii'),
                    'uid': g.user.id,
                    'full_name': g.user.get_full_name})


@app.route('/categories')
def categories():
    cats = [item.serialize for item in get_categories()]
    return jsonify(cats), 200


@app.route('/category/<int:category_id>')
def category(category_id):
    items = [item.serialize for item in get_items_by_category(category_id, 10)]
    return jsonify(items), 200


@app.route('/users/create', methods=['POST'])
def new_user():
    """
    Create a new user

    :return String: (JSON)
    """
    print request.json
    # Get user data
    data = request.json.get('data')
    username = data.get('username')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')

    # Check user data
    if len(username) < 3:
        return jsonify({'error': 'username too short'}), 200
    if len(password) < 8:
        return jsonify({'error': 'password must to be more 8 characters'})
    if len(first_name) < 2:
        return jsonify({'error': 'first name is too short, min 2 characters'})
    if len(last_name) < 2:
        return jsonify({'error': 'last name is too short, min 2 characters'})
    if email_is_valid(email) is False:
        return jsonify({'error': 'email is not valid'}), 200

    # Check user exist
    if user_exist(username):
        return jsonify({'error': 'user already exists'}), 200

    # Create a new user
    user = create_user(username, password, first_name, last_name, email) or None
    if user is None:
        return jsonify({'error': 'error create user'}), 200
    g.user = user

    # Data preparation
    data = {'message': 'User created',
            'id': g.user.id,
            'full_name': g.user.get_full_name}
    return jsonify(data), 201


@app.route('/profile/<int:uid>')
@auth.login_required
def profile(uid):
    """
    Return serializable users data

    :param uid:
    :return String: (JSON)
    """
    user = get_user_by_id(uid)
    return jsonify(user.serialize)


@app.route('/profile/edit/<int:uid>', methods=['POST'])
@auth.login_required
def edit_profile(uid):
    user_profile = get_user_by_id(uid)
    if user_profile.id != g.user.id:
        return jsonify({'error': 'permission denied'}), 403
    user = {
        'username': request.json.get('username'),
        'password': request.json.get('password'),
        'first_name': request.json.get('first_name'),
        'last_name': request.json.get('last_name'),
        'email': request.json.get('email'),
    }
    update_user(user)
    g.user = get_user_by_id(uid)
    return jsonify({'message': 'User %s was update!' % g.user.get_full_name})


@app.route('/profile/delete/<int:uid>', methods=['POST'])
@auth.login_required
def delete_user(uid):
    user_profile = get_user_by_id(uid)
    if user_profile.id != g.user.id:
        return jsonify({'error': 'permission denied'}), 403
    else:
        remove_user(uid)
        return jsonify({'message': 'account was removed'}), 200


@app.route('/create/item', methods=['POST'])
@auth.login_required
def new_item():

    # Get data
    title = request.json.get('title')
    description = request.json.get('description')
    category = request.json.get('category')
    author = request.json.get('author')

    # Check data
    if len(title) < 5:
        return jsonify({'error': 'too short title, minimum 5 characters'}), 206
    if len(description) < 5:
        return jsonify({'error': 'too short description, min 5 symbols'}), 206
    try:
        category = int(category)
    except Exception as e:
        return jsonify({'error': 'invalid category'}), 206
    if category < 1:
        return jsonify({'error': 'category not found'}), 206
    try:
        author = int(author)
    except Exception as e:
        return jsonify({'error': 'invalid author'}), 206
    if author < 1:
        return jsonify({'error': 'author not found'}), 206

    # Save data
    item = create_item(title, description, category, author, '/img.jpg')
    return jsonify({'message': 'Item: %s was added' % item.title}), 201


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
