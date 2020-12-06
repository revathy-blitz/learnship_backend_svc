import logging
import datetime
from uuid import uuid4
from botocore.exceptions import ClientError as BotoClientError
from flask import Blueprint, jsonify, request

from app.cognito import (login_user, logout_user, register_user,
                         validate_token, verify_user)
from app.exceptions import ClientError
from app.utils import check_params, decrypt_tokens, make_response, get_token_from_headers, upload_file_in_s3
from app.validators import validate_email_addr, validate_password
from app.extensions import db
from app.model import User, Blogs, FeedBack


API = Blueprint('api', __name__)

LOGGER = logging.getLogger(__name__)


@API.errorhandler(ClientError)
@API.errorhandler(BotoClientError)
def handle_validation_error(error):
    LOGGER.info(str(error))
    return make_response(status='error', message=error, status_code=400)


@API.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

@API.route('/verify', methods=['POST'])
def verify_view():

    required_params = {'email', 'confirmation_code'}

    if 'external_user' in request.path:
        required_params.add('xref_id')
    known_params = required_params

    data = request.get_json()

    check_params(required_params=required_params, known_params=known_params, data=data)

    data['email'] = data['email'].lower()

    verify_user(email=data['email'], confirmation_code=data['confirmation_code'])

    del data['confirmation_code']

    return make_response(status='success', message='Successfully verified user', status_code=200)


@API.route('/login', methods=['POST'])
def login_view():

    required_params = {'email', 'password'}
    known_params = required_params

    data = request.get_json()

    check_params(required_params=required_params, known_params=known_params, data=data)
    data['email'] = data['email'].lower()

    response = login_user(email=data['email'], password=data['password'])

    return make_response(status='success',
                         message='Successfully logged in',
                         data=response,
                         status_code=200)


@API.route('/logout', methods=['POST'])
def logout_view():

    required_params = {'tokens', }
    known_params = required_params

    data = request.get_json()

    check_params(required_params=required_params, known_params=known_params, data=data)

    tokens = data['tokens']
    tokens = decrypt_tokens(tokens=tokens)

    logout_user(tokens=tokens)

    return make_response(status='success', message='Successfully logged out', status_code=200)


@API.route('/validatetoken', methods=['POST'])
def validate_token_view():

    required_params = {'tokens'}
    known_params = required_params

    data = request.get_json()

    check_params(required_params=required_params, known_params=known_params, data=data)

    tokens = data['tokens']
    tokens = decrypt_tokens(tokens=tokens)

    response = validate_token(tokens=tokens)

    return make_response(status='success',
                         message='Tokens successfully validated',
                         data=response,
                         status_code=200)


@API.route('/register', methods=['POST'])
def register_view():
    required_params = {'email', 'password', 'first_name', 'last_name'}
    known_params = required_params

    data = request.get_json()

    check_params(required_params=required_params, known_params=known_params, data=data)
    data['email'] = data['email'].lower()

    if not validate_email_addr(email=data['email']):
        raise ClientError('Invalid email address')

    if not validate_password(password=data['password']):
        raise ClientError('Invalid password')

    response = register_user(first_name=data.get('first_name'),
                             last_name=data.get('last_name'),
                             email=data.get('email'),
                             password=data.get('password'))

    del data['password']
    data['external_id'] = response['UserSub']
    user_attributes = {
        'id': uuid4(),
        'first_name': data.get('first_name'),
        'last_name': data.get('last_name'),
        'email': data.get('email'),
        'external_id': response['UserSub'],
        'created': datetime.datetime.now()
    }

    User.create(**user_attributes)

    return make_response(status='success',
                         message='Successfully registered user',
                         status_code=200,
                         data=data)

@API.route('/account', methods=['GET'])
def account_view():
    tokens = get_token_from_headers()
    tokens = decrypt_tokens(tokens=tokens)
    response = validate_token(tokens=tokens)
    current_user = db.session.query(User).filter_by(email=response['email']).first()
    if not current_user:
        raise ClientError
    else:
        response = {
            'id': current_user.id,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name,
            'email': current_user.email,
            'superuser': current_user.superuser
        }
    return make_response(status='success',
                         message='Successfully registered user',
                         status_code=200,
                         data=response)

@API.route('/users', methods=['GET'])
def users_view():
    tokens = get_token_from_headers()
    tokens = decrypt_tokens(tokens=tokens)
    validate_token(tokens=tokens)
    users = db.session.query(User).all()
    if not users:
        raise ClientError
    return make_response(status='success',
                         message='Successfully registered user',
                         status_code=200,
                         data=[row.__dict__ for row in users])

@API.route('/blogs', methods=['GET', 'POST', 'DELETE'])
def blogs_view():
    tokens = get_token_from_headers()
    tokens = decrypt_tokens(tokens=tokens)
    LOGGER.info(tokens)
    validate_token(tokens=tokens)
    response = None
    if request.method == 'POST':
        required_params = {'title', 'subtitle', 'blog_content', 'media_url'}
        known_params = required_params

        data = request.get_json()

        check_params(required_params=required_params, known_params=known_params, data=data)
        blog_attributes = {
            'id': uuid4(),
            'title': data.get('title'),
            'subtitle': data.get('subtitle'),
            'blog_content': data.get('blog_content'),
            'media_url': data.get('media_url'),
            'created': datetime.datetime.now()
        }

        Blogs.create(**blog_attributes)
        response = [blog_attributes]

    elif request.method == 'DELETE':
        required_params = {'id'}
        data = request.get_json()
        blog = db.session.query(Blogs).filter_by(id=data.get('id')).first()
        LOGGER.info(blog)
        if blog:
            blog.delete()

    else:
        blog_id = request.args.get('id')
        blogs = []
        if blog_id:
            blogs = db.session.query(Blogs).filter_by(id=blog_id).all()
        else:
            blogs = db.session.query(Blogs).all()
        if not blogs:
            raise ClientError
        response = [row.__dict__ for row in blogs]

    return make_response(status='success',
                         message='Successfully registered user',
                         status_code=200,
                         data=response)

@API.route('/feedback', methods=['GET', 'POST', 'DELETE'])
def feed_view():
    # tokens = get_token_from_headers()
    # tokens = decrypt_tokens(tokens=tokens)
    # LOGGER.info(tokens)
    # validate_token(tokens=tokens)
    response = []
    if request.method == 'POST':
        required_params = {'account_id', 'blog_id', 'feedback'}
        known_params = required_params

        data = request.get_json()

        check_params(required_params=required_params, known_params=known_params, data=data)

        blog_attributes = {
            'id': uuid4(),
            'account_id': data.get('account_id'),
            'blog_id': data.get('blog_id'),
            'feedback': data.get('feedback'),
            'created': datetime.datetime.now()
        }

        FeedBack.create(**blog_attributes)
        response = [blog_attributes]

    elif request.method == 'DELETE':
        required_params = {'id'}
        data = request.get_json()
        feed = db.session.query(FeedBack).filter_by(id=data.get('id')).first()
        LOGGER.info(feed)
        if feed:
            feed.delete()

    else:
        blog_id = request.args.get('id')
        feed_id = request.args.get('feed_id')
        feeds = []
        feedback = db.session.query(FeedBack.id, FeedBack.feedback, FeedBack.created, User.first_name, User.last_name, User.email, Blogs.id) \
                    .distinct(FeedBack.id) \
                    .join(User, User.id == FeedBack.account_id) \
                    .join(Blogs, Blogs.id == FeedBack.blog_id)
        if feed_id:
            feeds = feedback.filter(FeedBack.id == feed_id).all()
        elif blog_id:
            feeds = feedback.filter(Blogs.id == blog_id).all()
        else:
            feeds = feedback.all()
            LOGGER.info(feeds)
        if not feeds:
            raise ClientError
        # response = [dict(row) for row in feeds]

        for row in feeds:
            res = {
                'id': row[0],
                'feedback': row[1],
                'created': row[2],
                'first_name': row[3],
                'last_name': row[4],
                'email': row[5],
                'blog_id': row[6]
            }
            response.append(res)

    return make_response(status='success',
                         message='Successfully registered user',
                         status_code=200,
                         data=response)


@API.route('/image', methods=['POST'])
def image_view():

    required_params = {'b64_binary_data'}
    known_params = required_params

    data = request.get_json()

    check_params(required_params=required_params, known_params=known_params, data=data)

    response = upload_file_in_s3(data=request.get_json())

    return make_response(status='success',
                         message='uploaded',
                         data=response,
                         status_code=200)
