#!/usr/bin/env python
# -*- coding: utf-8 -*-

from unittest import TestCase
from data_control import email_is_valid, get_path
from re import match, compile as re_compile


class TestFunctions(TestCase):

    def test_email_is_valid(self):
        result = email_is_valid('email@gmail.com')
        self.assertTrue(result)
        result = email_is_valid('email-gmail.com')
        self.assertFalse(result)

    def test_get_path(self):
        result = get_path('img.jpg', '/image')
        pattern = re_compile(r'^\/image\/\w{2}\/\w{2}\/\w{14}\.jpg$')
        self.assertTrue(pattern.match(result) is not None)


