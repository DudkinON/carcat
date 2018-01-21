#!/usr/bin/env python
# -*- coding: utf-8 -*-

from validate_email import validate_email
from random import choice
from string import ascii_uppercase as uppercase, digits
from settings import *


def allowed_file(filename, extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in extensions


def email_is_valid(email):
    """
    Check email is valid

    :param email:
    :return bool:
    """
    return validate_email(email)


def get_unique_str(amount):
    """
    Return a unique name string amount characters
    :return:
    """
    return ''.join(choice(uppercase + digits) for x in xrange(amount))


def get_path(filename, folder):
    """
    Generate a unique path to image like folder/xx/xx/xxxxxxxxxxxxxx.jpg

    :param filename:
    :param folder:
    :return string:
    """
    ext = filename.split('.')[-1]
    u_name = get_unique_str(18).lower()
    path = os.path.join(folder, u_name[:2], u_name[2:4])
    abs_path = ''.join([BASE_DIR, path])
    try:
        os.makedirs(abs_path)
    except OSError:
        pass

    full_path = os.path.join(folder, u_name[:2], u_name[2:4], u_name[4:])
    return '.'.join([full_path, ext])

