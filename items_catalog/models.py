#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired
from data_control import get_unique_str

Base = declarative_base()  # initialisation the database
secret_key = get_unique_str(32)  # create secret_key

# create session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# TODO: User model
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String(250), default='/img/no-img.png')
    first_name = Column(String(25), default=None)
    last_name = Column(String(25), default=None)
    email = Column(String(40))
    password_hash = Column(String(64))
    status = Column(String(10), default='user')

    def hash_password(self, password):
        """
        hash password

        :param password:
        :return void:
        """
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        """
        Password verification

        :param password:
        :return bool:
        """
        return pwd_context.verify(password, self.password_hash)

    @property
    def get_full_name(self):
        """
        Return ful name (first and last name)

        :return string:
        """
        return "%s %s" % (self.first_name, self.last_name)

    def generate_auth_token(self, expiration=600):
        """
        Generate authentication token

        :param expiration:
        :return string: (token)
        """
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'uid': self.id})

    @staticmethod
    def verify_auth_token(token):
        """
        Try to load token, success return user id false return None

        :param token:
        :return mix:
        """
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        uid = data['uid']
        return uid

    @property
    def serialize(self):
        """
        Return user data

        :return dict:
        """
        return {
            'id': self.id,
            'username': self.username,
            'picture': self.picture,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email
        }


# TODO: Image model
class Image(Base):
    __tablename__ = 'image'
    id = Column(Integer, primary_key=True)
    product = Column(Integer, nullable=False)
    url = Column(String(250))

    @property
    def serialize(self):
        """
        Return user data

        :return dict:
        """
        return {
            'id': self.id,
            'url': self.url
        }


# TODO: Category model
class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(30))

    @property
    def serialize(self):
        """
        Return user data

        :return dict:
        """
        return {
            'id': self.id,
            'name': self.name
        }


# TODO: Catalog model
class Catalog(Base):
    __tablename__ = 'catalog'
    id = Column(Integer, primary_key=True)
    model = Column(String(30))
    title = Column(String(250))
    description = Column(String(250))
    category = Column(Integer, ForeignKey("category.id"), nullable=False)
    price = Column(Integer, nullable=False)
    author = Column(Integer, ForeignKey("user.id"), nullable=False)

    def get_author(self):
        """
        Return product`s author

        :return object:
        """
        return session.query(User).filter_by(id=self.author).one().serialize

    def get_images(self):
        """
        Prepare list of images for JSON
        :return list:
        """
        images = session.query(Image).filter_by(product=self.id).all()
        return [img.serialize for img in images]

    @property
    def serialize(self):
        """
        Return user data

        :return dict:
        """
        return {
            'id': self.id,
            'model': self.model,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'price': self.price,
            'images': self.get_images(),
            'author': self.get_author(),
        }


# TODO: Database actions
def user_exist(username):
    """
    Check user exist

    :param username:
    :return bool:
    """
    if session.query(User).filter_by(username=username).first() is not None:
        return True
    else:
        return False


def get_user_by_email(email):
    """
    Return user by email or None

    :param email:
    :return object:
    """
    return session.query(User).filter_by(email=email).first() or None


def create_user(username, password, first_name, last_name, email,
                picture=None):
    """
    Create a new user

    :param username:
    :param password:
    :param first_name:
    :param last_name:
    :param picture:
    :param email:
    :return object:
    """
    user = User(username=username, first_name=first_name,
                last_name=last_name, email=email, picture=picture)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return user


def get_user_by_username(username):
    """
    Return user by username

    :param username:
    :return object:
    """
    return session.query(User).filter_by(username=username).first()


def get_user_by_id(uid):
    """
    Return user by user id

    :param uid:
    :return return:
    """
    return session.query(User).filter_by(id=uid).one()


def update_user(usr):
    """
    Update user

    :param usr:
    :return void:
    """
    session.query(User).filter_by(username=usr['username']).update(usr)


def remove_user(uid):
    """
    Remove user by user id

    :param uid:
    :return void:
    """
    user = session.query(User).filter_by(id=uid).first()
    session.delete(user)
    session.commit()


def create_category(name):
    """
    Create a new category

    :param name:
    :return object:
    """
    category = Category(name=name)
    session.add(category)
    session.commit()
    return category


def get_categories():
    """
    Return list of categories

    :return object:
    """
    return session.query(Category).all()


def update_category(category_id, name):
    """
    Change category name

    :param category_id:
    :param name:
    :return void:
    """
    session.query(Category).filter_by(id=category_id).first().update(name)


def remove_category(category_id):
    """
    Remove category

    :param category_id:
    :return void:
    """
    category = session.query(Category).filter_by(id=category_id).first()
    session.delete(category)
    session.commit()


def create_item(title, description, category, author, image):
    """
    Create item in catalog

    :param title:
    :param description:
    :param category:
    :param author:
    :param image:
    :return object:
    """
    item = Catalog(title=title, description=description,
                   category=category, author=author, image=image)
    session.add(item)
    session.commit()
    return item


def get_items(limit, offset=None):
    """
    Return items from catalog with limit and offset

    :param limit:
    :param offset:
    :return object:
    """
    return session.query(Catalog).offset(offset).limit(limit)


def get_items_by_category(category_id, limit, offset=None):
    """
    Return items from catalog by category with limit and offset

    :param category_id:
    :param limit:
    :param offset:
    :return object:
    """
    return session.query(Catalog).filter_by(
        category_id=category_id).offset(offset).limit(limit)


def get_item_by_id(item_id):
    """
    Return item by id

    :param item_id:
    :return object:
    """
    return session.query(Catalog).filter_by(id=item_id).first()


def update_item(item):
    """
    Update item

    :param item:
    :return void:
    """
    session.query(Catalog).filter_by(title=item['title']).first().update(item)


def delete_item(item_id):
    """
    Remove item by id

    :param item_id:
    :return void:
    """
    user = session.query(Catalog).filter_by(id=item_id).first()
    session.delete(user)
    session.commit()


Base.metadata.create_all(engine)
