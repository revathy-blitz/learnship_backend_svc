import logging

from flask import Flask
from werkzeug.contrib.fixers import ProxyFix

from app.api import API
from app.config import FLASK_ENV, DATABASE_URI, SQLALCHEMY_BINDS, SQLALCHEMY_ENGINE_OPTIONS
from app.extensions import cors, secure_headers, db
LOGGER = logging.getLogger(__name__)


def create_app(config_name=FLASK_ENV):
    app = Flask(__name__)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['SQLALCHEMY_ECHO'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
    app.config['SQLALCHEMY_BINDS'] = SQLALCHEMY_BINDS
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = SQLALCHEMY_ENGINE_OPTIONS
    register_blueprints(app)
    register_extensions(app)
    register_shellcontext(app)

    @app.after_request
    def set_secure_headers(response):  # pylint: disable=unused-variable
        secure_headers.flask(response)
        return response

    app.wsgi_app = ProxyFix(app.wsgi_app, num_proxies=2)

    return app


def register_blueprints(app):
    app.register_blueprint(API)


def register_extensions(app):
    # handling CORS
    cors.init_app(app=app, origins=[r'http://localhost:3100'])
    db.init_app(app)


def register_shellcontext(app):
    def shell_context():
        # return dict(app=app, db=DB)
        return dict(app=app)

    app.shell_context_processor(shell_context)
