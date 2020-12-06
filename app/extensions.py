from flask_cors import CORS
from secure import SecureHeaders
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
CONVENTION = {
    'ix': 'ix_%(column_0_label)s',
    'uq': 'uq_%(table_name)s_%(column_0_name)s',
    'ck': 'ck_%(table_name)s_%(constraint_name)s',
    'fk': 'fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s',
    'pk': 'pk_%(table_name)s'
}

# pylint: disable=invalid-name

cors = CORS()
secure_headers = SecureHeaders()
db = SQLAlchemy(metadata=MetaData(naming_convention=CONVENTION))
