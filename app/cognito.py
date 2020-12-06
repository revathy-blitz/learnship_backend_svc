from base64 import b64decode, b64encode
import json
from typing import Dict

from flask import current_app
from app.config import COGNITO_USER_POOL_ID, COGNITO_APP_CLIENT_ID, COGNITO_APP_CLIENT_SECRET
from jose import ExpiredSignatureError
from warrant import AWSSRP, Cognito

from app.utils import aws_key_dict, encrypt_tokens, get_claims, get_user_email
from app.validators import validate_password


def register_user(first_name: str,
                  last_name: str,
                  email: str,
                  password: str):

    user_pool_id = COGNITO_USER_POOL_ID
    client_id = COGNITO_APP_CLIENT_ID
    client_secret = COGNITO_APP_CLIENT_SECRET

    user = Cognito(user_pool_id,
                   client_id,
                   client_secret=client_secret,
                   username=str(email))

    # Whether or not there is a base attr requirement in cognito
    # config we have to add one or warrant will throw an error.
    user.add_base_attributes(email=email, given_name=first_name, family_name=last_name)

    response = user.register(email, password)

    return response

def verify_user(email: str, confirmation_code: str):
    user_pool_id = COGNITO_USER_POOL_ID
    client_id = COGNITO_APP_CLIENT_ID
    client_secret = COGNITO_APP_CLIENT_SECRET

    user = Cognito(user_pool_id,
                   client_id,
                   client_secret=client_secret,
                   username=email)
    response = user.confirm_sign_up(confirmation_code)

    return response

def login_user(email: str, password: str):
    user_pool_id = COGNITO_USER_POOL_ID
    client_id = COGNITO_APP_CLIENT_ID
    client_secret = COGNITO_APP_CLIENT_SECRET
    user_pool_region = user_pool_id.split('_')[0]

    # We're using warrant.AWSSRP not warrant.Cognito to get access token set.
    user = AWSSRP(pool_id=user_pool_id,
                  client_id=client_id,
                  client_secret=client_secret,
                  username=email,
                  password=password,
                  pool_region=user_pool_region)
    cog_res = user.authenticate_user()
    cog_res = cog_res['AuthenticationResult']
    tokens = {'id_token': cog_res['IdToken'],
              'refresh_token': cog_res['RefreshToken'],
              'access_token': cog_res['AccessToken']}
    access_token_claims = get_claims(user_pool_id,
                                     tokens['access_token'],
                                     keys=aws_key_dict(user_pool_id))
    response = dict()
    response['tokens'] = encrypt_tokens(tokens=tokens)
    # NOTE: Changes to user pool configuration may change
    # what is returned in access_token_claims['username']
    response['email'] = access_token_claims['username']
    response['sub'] = access_token_claims['sub']
    return response


def logout_user(tokens: Dict):
    user_pool_id = COGNITO_USER_POOL_ID
    client_id = COGNITO_APP_CLIENT_ID
    client_secret = COGNITO_APP_CLIENT_SECRET

    user = Cognito(user_pool_id,
                   client_id,
                   client_secret=client_secret,
                   id_token=tokens['id_token'],
                   refresh_token=tokens['refresh_token'],
                   access_token=tokens['access_token'])
    user.logout()


def validate_token(tokens: Dict):
    user_pool_id = COGNITO_USER_POOL_ID
    client_id = COGNITO_APP_CLIENT_ID
    client_secret = COGNITO_APP_CLIENT_SECRET

    _, info, _ = tokens['access_token'].split('.')
    info = json.loads(b64decode(info + '===').decode('UTF-8'))

    try:
        access_token_claims = get_claims(user_pool_id,
                                         tokens['access_token'],
                                         keys=aws_key_dict(user_pool_id))

        response = dict()
        response['tokens'] = encrypt_tokens(tokens=tokens)
        response['email'] = access_token_claims['username']
        response['sub'] = access_token_claims['sub']

    except ExpiredSignatureError:

        user = Cognito(user_pool_id,
                       client_id,
                       client_secret=client_secret,
                       access_token=tokens['access_token'],
                       refresh_token=tokens['refresh_token'],
                       id_token=tokens['id_token'],
                       username=info['username'])

        # Cognito.check_token() returns True if the access token is expired
        if user.check_token() is True:
            tokens['access_token'] = user.access_token
            tokens['id_token'] = user.id_token

        access_token_claims = get_claims(user_pool_id,
                                         tokens['access_token'],
                                         keys=aws_key_dict(user_pool_id))
        user_email = get_user_email(tokens['id_token'])

        response = dict()
        response['tokens'] = encrypt_tokens(tokens=tokens)
        response['email'] = user_email
        response['sub'] = access_token_claims['sub']
    return response
