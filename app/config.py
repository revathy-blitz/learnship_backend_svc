import logging
import os

LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

LOG_FORMAT = '%(asctime)s | %(name)-25s | %(levelname)-7s | %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
LOGGER = logging.getLogger(__name__)
LOGGER.info(f'Log Level: {LOG_LEVEL}')

FLASK_ENV = os.getenv('FLASK_ENV')

DATABASE_USERNAME = os.getenv('DATABASE_USERNAME')
DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
DATABASE_HOST = os.getenv('DATABASE_HOST')
DATABASE_PORT = int(os.getenv('DATABASE_PORT', 5432))
DATABASE_NAME = os.getenv('DATABASE_NAME')
DATABASE_URI = f'postgresql+psycopg2://{DATABASE_USERNAME}:' \
            f'{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}'

# Flask SQLAlchemy envs.
SQLALCHEMY_BINDS = {'test-db': DATABASE_URI}
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_recycle': int(os.getenv('SQLALCHEMY_POOL_RECYCLE', 3600)),
    'pool_size': int(os.getenv('SQLALCHEMY_POOL_SIZE', 10)),
    'max_overflow': int(os.getenv('SQLALCHEMY_MAX_OVERFLOW', 5))
}

S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

ENV = FLASK_ENV
COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_APP_CLIENT_ID = os.getenv('COGNITO_APP_CLIENT_ID')
COGNITO_APP_CLIENT_SECRET = os.getenv('COGNITO_APP_CLIENT_SECRET')
AES_KEY = os.getenv('AES_KEY')
