from flask import request
from base64 import b64decode, b64encode
from binascii import Error as binasciiError
import datetime
from functools import singledispatch
import json
from typing import Dict, Set
import zlib
import magic
import uuid
import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes  # type: ignore
from Crypto.Util.Padding import pad, unpad
import backoff
import boto3
from botocore.exceptions import ClientError
from flask import Response, current_app
from jose import jwt
import jwt as pyjwt
import requests
from app.exceptions import (ClientError, EmptyParamError, IncorrectDecryptionError,
                            MissingRequiredParamError, ServerError, UnsupportedParamError)
from app.config import COGNITO_USER_POOL_ID, AES_KEY, S3_BUCKET_NAME

def check_params(required_params: Set, known_params: Set, data: Dict):

    assert len(required_params.difference(known_params)) == 0

    check_for_required_params(required_params=required_params, params=data)
    check_for_empty_params(params=data)
    check_for_unknown_params(known_params=known_params, params=data)


def check_for_required_params(required_params: Set, params: Dict) -> None:

    if params is None:
        raise MissingRequiredParamError(params=required_params)

    provided_params = set(params.keys())
    missing_params = required_params.difference(provided_params)

    if missing_params:
        raise MissingRequiredParamError(params=missing_params)


def check_for_unknown_params(known_params: Set, params: Dict) -> None:

    provided_params = set(params.keys())
    unknown_params = provided_params.difference(known_params)

    if unknown_params:
        raise UnsupportedParamError(param=unknown_params)


def check_for_empty_params(params: Dict) -> None:
    empty_params = {key for key, value in params.items() if value == ''}

    if empty_params:
        raise EmptyParamError(params=empty_params)


def encrypt_tokens(tokens):
    aes_key = b64decode(AES_KEY)
    initialization_vector = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, IV=initialization_vector)

    tokens = json.dumps(tokens)
    tokens = bytes(tokens, 'UTF-8')
    tokens = zlib.compress(tokens, level=9)
    tokens = pad(tokens, AES.block_size)
    tokens = cipher.encrypt(tokens)
    tokens = initialization_vector + tokens
    tokens = b64encode(tokens).decode('UTF-8')

    return tokens


def decrypt_tokens(tokens):
    aes_key = b64decode(AES_KEY)
    try:
        tokens = b64decode(tokens)
    except binasciiError:
        raise IncorrectDecryptionError

    initialization_vector, tokens = tokens[0:16], tokens[16:]

    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, initialization_vector)
    except ValueError:
        raise IncorrectDecryptionError
    
    tokens = cipher.decrypt(tokens)
    tokens = unpad(tokens, AES.block_size)
    tokens = zlib.decompress(tokens)
    tokens = json.loads(tokens)

    return tokens


# Response Object Mod
@singledispatch
def to_serializable(val):
    """Use by default."""
    return str(val)


def make_response(status, message, status_code, **kwargs):
    """
    Format a Flask Response given a message, status, and status code.

    Additional key:value pairs can be included in the response object via keyword arguments.

    :param status: Status of call. Limited to 'success' or 'error'
    :param message: Message containing more detail about what happened.
    :param status_code: HTTP status code of response
    :param kwargs: key:value pairs to be included in the response object
    :return: Flask Response object
    """
    assert status in ('success', 'error')

    payload = {'status': status, 'message': message}
    payload = {**payload, **kwargs}
    json_str = json.dumps(payload, default=to_serializable)
    res = Response(json_str, status=status_code, mimetype='application/json')

    return res


def pool_url(aws_user_pool):
    aws_region = aws_user_pool.split('_')[0]
    return f'https://cognito-idp.{aws_region}.amazonaws.com/{aws_user_pool}'


@backoff.on_exception(wait_gen=backoff.constant,
                      exception=requests.exceptions.RequestException,
                      interval=1,
                      max_tries=5)
def get_url(url):
    return requests.get(url, timeout=(3.05, 5))


def aws_key_dict(aws_user_pool):
    jwks_url = pool_url(aws_user_pool) + '/.well-known/jwks.json'
    aws_data = get_url(jwks_url)
    aws_jwt = json.loads(aws_data.text)

    # We want a dictionary keyed by the kid, not a list.
    result = {}
    for item in aws_jwt['keys']:
        result[item['kid']] = item

    return result


def get_claims(aws_user_pool, token, keys=None, audience=None):
    """Validate and return the claims for the token."""
    # header, _, _ = get_token_segments(token)
    header = jwt.get_unverified_header(token)
    kid = header['kid']

    if keys is None:
        keys = aws_key_dict(aws_user_pool)

    key = keys.get(kid)

    if key is None:
        raise ClientError('Bad token')

    verify_url = pool_url(aws_user_pool)
    kargs = {'issuer': verify_url}

    if audience is not None:
        kargs['audience'] = audience

    claims = jwt.decode(token, key, **kargs)

    return claims


def get_user_email(id_token):
    """Pull the user email out of an id token."""
    payload = jwt.get_unverified_claims(id_token)
    user_email = payload['email']

    return user_email


def get_cognito_users(verified_only=False):
    session = boto3.Session()
    client = session.client('cognito-idp')
    params = {'UserPoolId': COGNITO_USER_POOL_ID,
              'Limit': 60}
    response = client.list_users(**params)
    user_list = response['Users']
    pagination_token = response.get('PaginationToken')
    while pagination_token:
        params.update({'PaginationToken': pagination_token})
        response = client.list_users(**params)
        user_list.extend(response['Users'])
        pagination_token = response.get('PaginationToken')

    if verified_only:
        return [x for x in user_list if x['UserStatus'] == 'CONFIRMED']
    return user_list


def get_api_users():
    key = get_secret(name='app-to-app-aes-key')
    payload = {'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60),
               'source': 'auth_service'}
    jwt_payload = pyjwt.encode(payload, key, algorithm='HS256')
    get_users_endpoint = current_app.config['CORE_API_URL'] + '/admin/get_users'
    response = requests.get(url=get_users_endpoint,
                            headers={'app-authentication': jwt_payload})
    response.raise_for_status()
    return response.json()['data']


@backoff.on_exception(wait_gen=backoff.constant,
                      exception=requests.exceptions.RequestException,
                      interval=1,
                      max_tries=5)
def create_api_user(data):
    create_user_url = current_app.config['CORE_API_URL'] + '/model/rest/user'
    response = requests.post(url=create_user_url,
                             json=data,
                             headers={'app-source': 'auth_service'},
                             timeout=(3.05, 27))

    return response.json()


def get_secret(name: str):
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager')  # ,region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=name)
    except ClientError:
        raise ServerError('Unable to securely authenticate')

    secret = get_secret_value_response['SecretString']

    return secret


@backoff.on_exception(wait_gen=backoff.constant,
                      exception=requests.exceptions.RequestException,
                      interval=1,
                      max_tries=3)

def create_subscription_for_user(data: dict):
    admin_key = current_app.config['SUBSCRIPTION_AUTH_KEY']
    subscription_url = f"{current_app.config['SAP_API_URL']}/subscription/add/external_user"
    response = requests.post(url=subscription_url,
                             json=data,
                             headers={'x-admin-key': admin_key},
                             timeout=(3.05, 27))
    response.raise_for_status()
    return response

def get_token_from_headers():
    if 'Authorization' in request.headers:
        token = request.headers['Authorization']
        return token
    else:
        raise ClientError('Not Authorized')

def write_to_bucket(file_extension, content_type, b64_binary_data):
    aws_s3_bucket_name = S3_BUCKET_NAME

    binary_data = b64decode(b64_binary_data)
    s3_object_name = uuid.uuid4().hex + '.' + file_extension

    s3_client = boto3.client('s3')
    s3_client.put_object(Bucket=aws_s3_bucket_name,
                         Key=s3_object_name,
                         ContentType=content_type,
                         Metadata={'image_hash': hashlib.md5(binary_data).hexdigest()},
                         Body=binary_data,
                         ACL='public-read',)

    return f'{s3_client.meta.endpoint_url}/{aws_s3_bucket_name}/{s3_object_name}'


MIMETYPE_MAP = {'application/pdf': 'pdf',
                'image/gif': 'gif',
                'image/jpeg': 'jpg',
                'image/png': 'png'}

def upload_file_in_s3(data) -> str:
    json_data = data

    if len({'b64_binary_data', 'url'}.intersection(set(json_data.keys()))) == 0:
        raise ClientError(msg='Missing one of params: "b64_binary_data"')


    if 'b64_binary_data' in json_data:
        b64_binary_data = json_data['b64_binary_data']
        try:
            image = b64decode(b64_binary_data)
        except binasciiError:
            raise ClientError
        content_type = magic.from_buffer(image, mime=True)

    extension = MIMETYPE_MAP.get(content_type)
    if extension is None:
        raise ClientError

    internal_url = write_to_bucket(extension, content_type, b64_binary_data)
    response = {'url': internal_url}
    return response
