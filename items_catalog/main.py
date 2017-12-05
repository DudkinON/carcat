#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, abort, g
from models import create_user, get_user_by_username, create_category
from models import create_item, User, get_items_by_category, update_user_photo
from models import get_categories, get_items, get_user_by_email, check_category
from models import user_exist, update_user, remove_user, get_user_by_id
from data_control import email_is_valid, get_unique_str, get_path, allowed_file
from settings import *
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from bleach import clean
from httplib2 import Http
from flask import make_response
from requests import get as r_get
from json import dumps, loads

ALLOWED_EXTENSIONS = set(EXTENSIONS)
auth = HTTPBasicAuth()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# TODO: Verification of password
@auth.verify_password
def verify_password(_login, password):
    """
    Verification of password

    :param _login:
    :param password:
    :return bool:
    """
    # Try to see if it's a token first
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


# TODO: Sign in with provider
@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    # STEP 1 - Parse the auth code
    code = request.data

    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
        access_token)
        h = Http()
        result =loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # Get user info
        h = Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = r_get(userinfo_url, params=params)

        data = answer.json()
        print data

        # see if user exists, if it doesn't make a new one
        user = get_user_by_email(email=data['email'])
        if not user:
            user = create_user(username=data.get('name'),
                               picture=data.get('picture'),
                               email=data.get('email'),
                               first_name=data.get('given_name'),
                               last_name=data.get('family_name'),
                               password=get_unique_str(8))

        g.user = user
        # Make token
        token = g.user.generate_auth_token()

        # Send back token to the client
        return jsonify({'token': token.decode('ascii'),
                        'uid': g.user.id,
                        'first_name': g.user.first_name,
                        'last_name': g.user.last_name,
                        'email': g.user.email,
                        'picture': g.user.picture,
                        'status': g.user.status,
                        'full_name': g.user.get_full_name}), 200

    elif provider == 'facebook':

        data = request.json.get('data')
        access_token = data['access_token']
        fb_file = ''.join([BASE_DIR, '/items_catalog/facebook.json'])
        fb_data = loads(open(fb_file, 'r').read())['facebook']
        app_id = fb_data['app_id']
        app_secret = fb_data['app_secret']
        url = fb_data['access_token_url'] % (app_id, app_secret, access_token)
        h = Http()
        result = h.request(url, 'GET')[1]

        # Use token to get user info from API

        '''
            Due to the formatting for the result from the server token exchange
            we have to split the token first on commas and select the first 
            index which gives us the key : value for the server access token 
            then we split it on colons to pull out the actual token value
            and replace the remaining quotes with nothing so that it can be 
            used directly in the graph api calls
        '''
        token = result.split(',')[0].split(':')[1].replace('"', '')
        url = fb_data['user_info_url'] % token

        h = Http()
        result = h.request(url, 'GET')[1]
        data = loads(result)
        name = data['name'].split(' ')

        user_data = dict()
        user_data['provider'] = 'facebook'
        user_data['username'] = data.get('name')
        user_data['first_name'] = name[0]
        user_data['last_name'] = name[1]
        user_data['email'] = data.get('email')
        user_data['facebook_id'] = data.get('id')
        user_data['access_token'] = token

        url = fb_data['picture_url'] % token
        h = Http()
        result = h.request(url, 'GET')[1]
        data = loads(result)
        user_data['picture'] = data['data']['url']
        # login_session['picture'] = data["data"]["url"]

        # see if user exists
        user_info = get_user_by_email(user_data['email'])

        if user_info is None:
            user_info = create_user(username=user_data['username'],
                                    password=get_unique_str(8),
                                    first_name=user_data['first_name'],
                                    last_name=user_data['last_name'],
                                    email=user_data['email'],
                                    picture=user_data['picture'])

        g.user = user_info
        token = g.user.generate_auth_token()
        return jsonify({'token': token.decode('ascii'),
                        'uid': g.user.id,
                        'first_name': g.user.first_name,
                        'last_name': g.user.last_name,
                        'email': g.user.email,
                        'picture': g.user.picture,
                        'status': g.user.status,
                        'full_name': g.user.get_full_name}), 200

    else:
        return jsonify({'error': 'Unknown provider'}), 200


# TODO: Home page
@app.route('/')
def home_page():
    items = get_items(limit=10)
    json = [item.serialize for item in items]
    print request.headers
    # print {item.serialize for item in items}

    return jsonify(json)


# TODO: Get categories
@app.route('/categories')
def categories():
    cats = [item.serialize for item in get_categories()]
    return jsonify(cats), 200


# TODO: Get items by category
@app.route('/category/<int:category_id>')
def category(category_id):
    items = [item.serialize for item in get_items_by_category(category_id, 10)]
    return jsonify(items), 200


# TODO: Add new category
@app.route('/category/new', methods=['POST'])
@auth.login_required
def add_category():
    if g.user.status is not 'admin':
        return jsonify({'error': "You do not have permission to do that"}), 200
    new_category = clean(request.json.get('name'))
    if check_category(new_category):
        create_category(new_category)
    cats = [item.serialize for item in get_categories()]
    return jsonify(cats), 200


# TODO: Get auth token
@app.route('/token')
@auth.login_required
def get_auth_token():
    print "headers: "
    print request.headers
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii'),
                    'uid': g.user.id,
                    'picture': g.user.picture,
                    'first_name': g.user.first_name,
                    'last_name': g.user.last_name,
                    'status': g.user.status,
                    'email': g.user.email,
                    'full_name': g.user.get_full_name})


# TODO: Create a new user
@app.route('/users/create', methods=['POST'])
def new_user():
    """
    Create a new user

    :return String: (JSON)
    """
    print request.json
    # Get user data
    data = request.json.get('data')
    username = clean(data.get('username'))
    password = clean(data.get('password'))
    first_name = clean(data.get('first_name'))
    last_name = clean(data.get('last_name'))
    email = clean(data.get('email'))

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


# TODO: Get a profile info by uid
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


# TODO: Edit user data
@app.route('/profile/edit/photo/<int:uid>', methods=['POST'])
@auth.login_required
def edit_photo(uid):
    user_profile = get_user_by_id(uid)
    if user_profile.id != g.user.id:
        return jsonify({'error': 'permission denied'}), 403

    # check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'error': "Server don't get image"})
    photo = request.files['file']
    # if user does not select file, browser also
    # submit a empty part without filename
    if photo.filename == '':
        return jsonify({'error': 'No selected file'}), 200
    if photo and allowed_file(photo.filename, ALLOWED_EXTENSIONS):
        filename = get_path(filename=secure_filename(photo.filename),
                            folder=app.config['UPLOAD_FOLDER'])

        abs_path = '%s%s' % (BASE_DIR, filename)
        print abs_path
        photo.save(abs_path)
        user = update_user_photo(filename, g.user.id)
        g.user = user
        return jsonify(user.serialize), 200
    else:
        return jsonify({'error', "Can't update user photo"}), 200


# TODO: Edit user data
@app.route('/profile/edit/<int:uid>', methods=['POST'])
@auth.login_required
def edit_profile(uid):
    user_profile = get_user_by_id(uid)
    if user_profile.id != g.user.id:
        return jsonify({'error': 'permission denied'}), 403

    # define user object
    user = {
        'username': clean(request.json.get('username')),
        'password': clean(request.json.get('password')),
        'first_name': clean(request.json.get('first_name')),
        'last_name': clean(request.json.get('last_name')),
        'email': clean(request.json.get('email')),
    }

    # update user
    update_user(user)
    g.user = get_user_by_id(uid)
    return jsonify({'message': 'User %s was update!' % g.user.get_full_name})


# TODO: Delete an user
@app.route('/profile/delete/<int:uid>', methods=['POST'])
@auth.login_required
def delete_user(uid):
    user_profile = get_user_by_id(uid)
    if user_profile.id != g.user.id:
        return jsonify({'error': 'permission denied'}), 403
    else:
        remove_user(uid)
        return jsonify({'message': 'account was removed'}), 200


# TODO: Create a new item
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
