# coding: utf-8
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import false
from sqlalchemy import ForeignKey
from sqlalchemy import Unicode
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql.expression import text
from uuid import uuid4

from app.extensions import db

class CRUDMixin(object):
    """Mixin that adds convenience methods for CRUD (create, read, update, delete) operations."""

    @classmethod
    def create(cls, **kwargs):
        """Create a new record and save it the database."""
        instance = cls(**kwargs)
        return instance.save()

    def update(self, commit=True, **kwargs):
        """Update specific fields of a record."""
        for attr, value in kwargs.items():
            setattr(self, attr, value)
        return commit and self.save() or self

    def save(self, commit=True):
        """Save the record."""
        db.session.add(self)
        if commit:
            db.session.commit()
        return self

    def delete(self, commit=True):
        """Remove the record from the database."""
        db.session.delete(self)
        return commit and db.session.commit()

class UUIDPK(object):
    """Mixin that adds a UUID primary key to a model.  Relies on Postgres extension 'uuid-ossp'."""

    id = Column('id',
                UUID(as_uuid=True),
                primary_key=True,
                default=uuid4(),
                server_default=text('uuid_generate_v4()'))

    @classmethod
    def get_by_id(cls, record_id):
        return cls.query.get(int(record_id))


class Model(UUIDPK, CRUDMixin, db.Model):
    """Base model class that includes CRUD convenience methods."""

    __abstract__ = True


class User(Model):
    __bind_key__ = 'test-db'
    __tablename__ = 'account'
    __table_args__ = {'schema': 'public', 'extend_existing': True}

    id = Column(UUID(as_uuid=True), primary_key=True)
    first_name = Column(Unicode, nullable=False)
    last_name = Column(Unicode, nullable=False)
    email = Column(Unicode, nullable=False)
    external_id = Column(Unicode, unique=True, nullable=False)
    superuser = Column(Boolean, default=False,
                       server_default=false(), nullable=False)
    created = Column(DateTime, nullable=False)
    updated = Column(DateTime, nullable=True)


class Blogs(Model):
    __bind_key__ = 'test-db'
    __tablename__ = 'blogs'
    __table_args__ = {'schema': 'public', 'extend_existing': True}

    id = Column(UUID(as_uuid=True), primary_key=True)
    title = Column(Unicode, nullable=False)
    subtitle = Column(Unicode, nullable=False)
    blog_content = Column(Unicode, nullable=False)
    media_url = Column(Unicode, nullable=True)
    created = Column(DateTime, nullable=False)
    updated = Column(DateTime, nullable=True)


class FeedBack(Model):
    __bind_key__ = 'test-db'
    __tablename__ = 'feedback'
    __table_args__ = {'schema': 'public', 'extend_existing': True}

    id = Column(UUID(as_uuid=True), primary_key=True)
    account_id = Column(Unicode, unique=True, nullable=False)
    blog_id = Column(Unicode, unique=True, nullable=False)
    feedback = Column(Unicode, nullable=False)
    created = Column(DateTime, nullable=False)
    updated = Column(DateTime, nullable=True)
